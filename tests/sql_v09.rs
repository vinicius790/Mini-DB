//! 0.9: busca avançada — full-text (BM25), vetorial (HNSW) e espacial (curva Z).
use mini_db::{Db, ExecResult};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("minidb-sql09-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn rows_of(res: ExecResult) -> Vec<String> {
    match res {
        ExecResult::Table { rows, .. } => rows
            .iter()
            .map(|r| {
                r.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .collect(),
        other => panic!("{other:?}"),
    }
}

fn q(db: &mut Db, sql: &str) -> Vec<String> {
    rows_of(db.execute_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}")))
}

fn ok(db: &mut Db, sql: &str) -> String {
    match db.execute_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}")) {
        ExecResult::Ok(s) => s,
        ExecResult::Batch(_) => String::new(),
        other => panic!("{sql}: {other:?}"),
    }
}

fn err(db: &mut Db, sql: &str) -> String {
    match db.execute_sql(sql) {
        Err(e) => e.to_string(),
        Ok(r) => panic!("{sql} devia falhar, devolveu {r:?}"),
    }
}

fn plan(db: &mut Db, sql: &str) -> String {
    ok(db, &format!("EXPLAIN {sql}"))
}

fn docs(tag: &str) -> Db {
    let mut db = Db::open(tmpdir(tag)).unwrap();
    ok(
        &mut db,
        "CREATE TABLE docs (id INT PRIMARY KEY, title TEXT, body TEXT, lang TEXT)",
    );
    ok(
        &mut db,
        "INSERT INTO docs VALUES
         (1, 'Motor de física', 'Colisões e corpos rígidos no motor do jogo', 'pt'),
         (2, 'Shaders', 'Iluminação e sombras em tempo real com shaders', 'pt'),
         (3, 'Game loop', 'The game loop updates physics and renders frames', 'en'),
         (4, 'Física avançada', 'Simulação de fluidos e partículas no motor', 'pt'),
         (5, 'Áudio', 'Mixagem espacial de áudio para jogos', 'pt')",
    );
    ok(
        &mut db,
        "CREATE FULLTEXT INDEX docs_fts ON docs (title, body)",
    );
    db
}

#[test]
fn fulltext_match_uses_index_and_ranks_by_bm25() {
    let mut db = docs("fts");
    let sql = "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('motor física') ORDER BY id";
    assert!(
        plan(&mut db, sql).contains("FULLTEXT INDEX docs_fts"),
        "{}",
        plan(&mut db, sql)
    );
    assert_eq!(q(&mut db, sql), ["1", "4"]);
    // Ranking BM25: "motor" duas vezes (título e corpo) pontua mais que uma;
    // com frequência igual, o documento mais curto vence.
    let ranked = q(
        &mut db,
        "SELECT id, MATCH (title, body) AGAINST ('motor') > 0 FROM docs
         WHERE MATCH (title, body) AGAINST ('motor')
         ORDER BY MATCH (title, body) AGAINST ('motor') DESC, id",
    );
    assert_eq!(ranked, ["1|true", "4|true"]);
    let ranked = q(
        &mut db,
        "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('física')
         ORDER BY MATCH (title, body) AGAINST ('física') DESC",
    );
    assert_eq!(ranked, ["4", "1"]);
    // Radicalização: "colisão" acha "Colisões"; prefixo e frase.
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('colisão')"
        ),
        ["1"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('shad*') ORDER BY id"
        ),
        ["2"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('\"game loop\"')"
        ),
        ["3"]
    );
    assert!(q(
        &mut db,
        "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('\"loop game\"')"
    )
    .is_empty());
    // OR e exclusão.
    assert_eq!(
        q(&mut db, "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('áudio OR shaders') ORDER BY id"),
        ["2", "5"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('motor -fluidos')"
        ),
        ["1"]
    );
    // Sem índice nas colunas pedidas: avalia linha a linha (mesmo resultado).
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM docs WHERE MATCH (body) AGAINST ('motor') ORDER BY id"
        ),
        ["1", "4"]
    );
    assert!(!plan(
        &mut db,
        "SELECT id FROM docs WHERE MATCH (body) AGAINST ('motor')"
    )
    .contains("FULLTEXT"));
    // Funções auxiliares.
    assert_eq!(
        q(
            &mut db,
            "SELECT fts_highlight('Motor do jogo', 'motor', '[', ']')"
        ),
        ["[Motor] do jogo"]
    );
    assert_eq!(
        q(&mut db, "SELECT fts_tokens('Os Jogos, rodando!')"),
        ["[\"os\",\"jogo\",\"rodando\"]"]
    );
}

#[test]
fn fulltext_index_follows_updates_deletes_and_reindex() {
    let mut db = docs("fts-dml");
    ok(
        &mut db,
        "UPDATE docs SET body = 'Renderização de terreno' WHERE id = 1",
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('colisões')"
        )
        .len(),
        0
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('terreno')"
        ),
        ["1"]
    );
    ok(&mut db, "DELETE FROM docs WHERE id = 4");
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('motor')"
        ),
        ["1"]
    );
    // Transação desfeita não deixa rastro no índice.
    ok(&mut db, "BEGIN");
    ok(
        &mut db,
        "INSERT INTO docs VALUES (9, 'Rede', 'Sincronização de rede', 'pt')",
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('rede')"
        ),
        ["9"]
    );
    ok(&mut db, "ROLLBACK");
    assert!(q(
        &mut db,
        "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('rede')"
    )
    .is_empty());
    assert!(ok(&mut db, "REINDEX docs_fts").starts_with("REINDEX docs_fts rows=4"));
    assert!(ok(&mut db, "REINDEX docs").starts_with("REINDEX docs"));
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM docs WHERE MATCH (title, body) AGAINST ('shaders')"
        ),
        ["2"]
    );
    let show = q(&mut db, "SHOW INDEXES ON docs");
    assert!(
        show.iter()
            .any(|r| r.contains("docs_fts") && r.ends_with("fulltext")),
        "{show:?}"
    );
    let ddl = q(&mut db, "SHOW CREATE TABLE docs").join("\n");
    assert!(
        ddl.contains("CREATE FULLTEXT INDEX docs_fts ON docs (title, body);"),
        "{ddl}"
    );
    // Erros.
    assert!(err(&mut db, "CREATE UNIQUE FULLTEXT INDEX x ON docs (title)").contains("UNIQUE"));
}

fn vec_db(tag: &str, metric: &str) -> Db {
    let mut db = Db::open(tmpdir(tag)).unwrap();
    ok(
        &mut db,
        "CREATE TABLE items (id INT PRIMARY KEY, emb TEXT, tag TEXT)",
    );
    ok(
        &mut db,
        &format!("CREATE VECTOR INDEX items_emb ON items (emb) WITH (metric = '{metric}', dims = 3, m = 8)"),
    );
    let mut sql = String::from("INSERT INTO items VALUES ");
    for i in 0..300 {
        let a = (i as f64 * 0.37).sin();
        let b = (i as f64 * 0.11).cos();
        let c = (i as f64 * 0.05).sin() * 0.5;
        if i > 0 {
            sql.push(',');
        }
        sql.push_str(&format!(
            "({i}, '[{a:.4}, {b:.4}, {c:.4}]', '{}')",
            if i % 2 == 0 { "par" } else { "impar" }
        ));
    }
    ok(&mut db, &sql);
    db
}

fn brute(db: &mut Db, metric: &str, query: &str, k: usize) -> Vec<String> {
    q(
        db,
        &format!("SELECT id FROM items ORDER BY vec_distance(emb, '{query}', '{metric}') + 0, id LIMIT {k}"),
    )
}

#[test]
fn vector_knn_uses_hnsw_and_matches_exact_top_k() {
    for metric in ["cosine", "l2", "dot"] {
        let mut db = vec_db(&format!("vec-{metric}"), metric);
        let query = "[0.3, 0.9, -0.1]";
        let op = match metric {
            "cosine" => "<=>",
            "l2" => "<->",
            _ => "<#>",
        };
        let sql = format!("SELECT id FROM items ORDER BY emb {op} '{query}' LIMIT 5");
        let p = plan(&mut db, &sql);
        assert!(p.contains("VECTOR INDEX items_emb"), "{metric}: {p}");
        let approx = q(&mut db, &sql);
        // Força a varredura (sem índice aplicável) para o gabarito exato.
        let exact: Vec<String> = q(
            &mut db,
            &format!("SELECT id FROM items ORDER BY vec_distance(emb, '{query}', '{metric}') + 0 LIMIT 5"),
        );
        assert_eq!(approx.len(), 5);
        let hits = approx.iter().filter(|a| exact.contains(a)).count();
        assert!(hits >= 4, "{metric}: aproximado {approx:?} exato {exact:?}");
        assert_eq!(approx[0], exact[0], "{metric}: vizinho mais próximo");
    }
}

#[test]
fn vector_index_handles_filters_updates_and_deletes() {
    let mut db = vec_db("vec-dml", "l2");
    let query = "[0.3, 0.9, -0.1]";
    let filtered = q(
        &mut db,
        &format!("SELECT id, tag FROM items WHERE tag = 'par' ORDER BY emb <-> '{query}' LIMIT 3"),
    );
    assert_eq!(filtered.len(), 3);
    assert!(filtered.iter().all(|r| r.ends_with("|par")), "{filtered:?}");
    let first = brute(&mut db, "l2", query, 1)[0].clone();
    ok(&mut db, &format!("DELETE FROM items WHERE id = {first}"));
    let after = q(
        &mut db,
        &format!("SELECT id FROM items ORDER BY emb <-> '{query}' LIMIT 1"),
    );
    assert_ne!(after[0], first);
    assert_eq!(after, brute(&mut db, "l2", query, 1));
    ok(
        &mut db,
        &format!("UPDATE items SET emb = '{query}' WHERE id = 7"),
    );
    assert_eq!(
        q(
            &mut db,
            &format!("SELECT id FROM items ORDER BY emb <-> '{query}' LIMIT 1")
        ),
        ["7"]
    );
    // Apagar tudo e reinserir: ponto de entrada é recriado.
    ok(&mut db, "DELETE FROM items WHERE id < 250");
    assert_eq!(q(&mut db, "SELECT count(*) FROM items"), ["50"]);
    let top = q(
        &mut db,
        &format!("SELECT id FROM items ORDER BY emb <-> '{query}' LIMIT 2"),
    );
    assert_eq!(top, brute(&mut db, "l2", query, 2));
    ok(&mut db, "DELETE FROM items");
    assert!(q(
        &mut db,
        &format!("SELECT id FROM items ORDER BY emb <-> '{query}' LIMIT 2")
    )
    .is_empty());
    ok(
        &mut db,
        "INSERT INTO items VALUES (1, '[1, 0, 0]', 'a'), (2, '[0, 1, 0]', 'b')",
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM items ORDER BY emb <-> '[0.9, 0.1, 0]' LIMIT 1"
        ),
        ["1"]
    );
    // Dimensões erradas e métrica desconhecida.
    assert!(err(&mut db, "INSERT INTO items VALUES (3, '[1, 0]', 'c')").contains("dimensões"));
    assert!(err(
        &mut db,
        "CREATE VECTOR INDEX x ON items (emb) WITH (metric = 'manhattan')"
    )
    .contains("métrica"));
    assert!(err(&mut db, "CREATE VECTOR INDEX x ON items (emb, tag)").contains("uma coluna"));
    // Funções vetoriais.
    assert_eq!(
        q(&mut db, "SELECT vec_dims('[1,2,3]'), vec_norm('[3,4]')"),
        ["3|5.0"]
    );
    assert_eq!(q(&mut db, "SELECT vec_normalize('[3, 4]')"), ["[0.6,0.8]"]);
    assert_eq!(
        q(
            &mut db,
            "SELECT '[1,2]' <-> '[1,2]', '[1,0]' <=> '[0,1]', '[1,2]' <#> '[3,4]'"
        ),
        ["0.0|1.0|-11.0"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT vec_add('[1,2]', '[3,4]'), vec_sub('[1,2]', '[3,4]')"
        ),
        ["[4,6]|[-2,-2]"]
    );
    let ddl = q(&mut db, "SHOW CREATE TABLE items").join("\n");
    assert!(ddl.contains("CREATE VECTOR INDEX items_emb ON items (emb) WITH (dims = '3', m = '8', metric = 'l2');"), "{ddl}");
}

#[test]
fn spatial_index_answers_box_and_radius_queries() {
    let mut db = Db::open(tmpdir("spatial")).unwrap();
    ok(
        &mut db,
        "CREATE TABLE pts (id INT PRIMARY KEY, x REAL, y REAL, name TEXT)",
    );
    let mut sql = String::from("INSERT INTO pts VALUES ");
    for i in 0..2000 {
        let x = (i % 50) as f64 * 2.0 - 50.0;
        let y = (i / 50) as f64 * 2.5 - 50.0;
        if i > 0 {
            sql.push(',');
        }
        sql.push_str(&format!("({i}, {x}, {y}, 'p{i}')"));
    }
    ok(&mut db, &sql);
    let exact = |db: &mut Db, filter: &str| {
        q(
            db,
            &format!("SELECT id FROM pts WHERE {filter} ORDER BY id"),
        )
    };
    let box_filter = "x BETWEEN -3 AND 4.5 AND y >= 0 AND y < 7";
    let before = exact(&mut db, box_filter);
    ok(&mut db, "CREATE SPATIAL INDEX pts_xy ON pts (x, y)");
    let p = plan(&mut db, &format!("SELECT id FROM pts WHERE {box_filter}"));
    assert!(p.contains("SPATIAL INDEX pts_xy"), "{p}");
    assert_eq!(exact(&mut db, box_filter), before);
    assert!(!before.is_empty());
    // Raio: st_dwithin vira caixa no plano e filtro exato depois.
    let radius = "st_dwithin(x, y, 10, 10, 6)";
    let p = plan(&mut db, &format!("SELECT id FROM pts WHERE {radius}"));
    assert!(p.contains("SPATIAL INDEX"), "{p}");
    let got = exact(&mut db, radius);
    let check = q(
        &mut db,
        "SELECT id FROM pts WHERE st_distance(x, y, 10, 10) <= 6 + 0 ORDER BY id",
    );
    assert_eq!(got, check);
    assert!(!got.is_empty());
    // Faixa aberta num eixo não usa o índice (caixa infinita).
    assert!(!plan(&mut db, "SELECT id FROM pts WHERE x > 3").contains("SPATIAL"));
    // Manutenção.
    ok(&mut db, "UPDATE pts SET x = 500, y = 500 WHERE id = 0");
    assert_eq!(
        exact(&mut db, "x BETWEEN 499 AND 501 AND y BETWEEN 499 AND 501"),
        ["0"]
    );
    ok(&mut db, "DELETE FROM pts WHERE id = 0");
    assert!(exact(&mut db, "x BETWEEN 499 AND 501 AND y BETWEEN 499 AND 501").is_empty());
    // 3D e validação.
    ok(
        &mut db,
        "CREATE TABLE vox (id INT PRIMARY KEY, x INT, y INT, z INT)",
    );
    ok(&mut db, "CREATE SPATIAL INDEX vox_xyz ON vox (x, y, z)");
    ok(
        &mut db,
        "INSERT INTO vox VALUES (1, 1, 1, 1), (2, 5, 5, 5), (3, 1, 1, 9)",
    );
    assert_eq!(
        q(&mut db, "SELECT id FROM vox WHERE x BETWEEN 0 AND 2 AND y BETWEEN 0 AND 2 AND z BETWEEN 0 AND 2"),
        ["1"]
    );
    assert!(err(&mut db, "CREATE SPATIAL INDEX bad ON pts (x)").contains("2 ou 3"));
    assert!(err(&mut db, "CREATE SPATIAL INDEX bad ON pts (x, name)").contains("numéricas"));
    assert_eq!(
        q(
            &mut db,
            "SELECT round(st_distance_sphere(0, 0, 0, 1) / 1000)"
        ),
        ["111.0"]
    );
}

#[test]
fn special_indexes_survive_reopen_and_drop() {
    let dir = tmpdir("reopen");
    {
        let mut db = Db::open(&dir).unwrap();
        ok(
            &mut db,
            "CREATE TABLE d (id INT PRIMARY KEY, t TEXT, e TEXT, x REAL, y REAL)",
        );
        ok(&mut db, "CREATE FULLTEXT INDEX d_t ON d (t)");
        ok(&mut db, "CREATE VECTOR INDEX d_e ON d (e)");
        ok(&mut db, "CREATE SPATIAL INDEX d_xy ON d (x, y)");
        ok(&mut db, "INSERT INTO d VALUES (1, 'gato preto', '[1,0]', 1, 1), (2, 'cão branco', '[0,1]', 5, 5)");
    }
    let mut db = Db::open(&dir).unwrap();
    assert_eq!(
        q(&mut db, "SELECT id FROM d WHERE MATCH (t) AGAINST ('gato')"),
        ["1"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM d ORDER BY e <=> '[0.1, 1]' LIMIT 1"
        ),
        ["2"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM d WHERE x BETWEEN 4 AND 6 AND y BETWEEN 4 AND 6"
        ),
        ["2"]
    );
    let plan_v = plan(
        &mut db,
        "SELECT id FROM d ORDER BY e <=> '[0.1, 1]' LIMIT 1",
    );
    assert!(plan_v.contains("VECTOR INDEX d_e (cosine)"), "{plan_v}");
    ok(&mut db, "DROP INDEX d_e");
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM d ORDER BY e <=> '[0.1, 1]' LIMIT 1"
        ),
        ["2"]
    );
    assert!(!plan(
        &mut db,
        "SELECT id FROM d ORDER BY e <=> '[0.1, 1]' LIMIT 1"
    )
    .contains("VECTOR"));
    ok(&mut db, "TRUNCATE TABLE d");
    assert!(q(&mut db, "SELECT id FROM d WHERE MATCH (t) AGAINST ('gato')").is_empty());
    ok(&mut db, "INSERT INTO d VALUES (3, 'gato', '[1,1]', 0, 0)");
    assert_eq!(
        q(&mut db, "SELECT id FROM d WHERE MATCH (t) AGAINST ('gato')"),
        ["3"]
    );
    ok(&mut db, "DROP TABLE d");
}
