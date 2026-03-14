# Testing

To accept all new snapshots, run `INSTA_UPDATE=always cargo test` or to accept only for new tests, run `INSTA_UPDATE=unseen cargo test`.

## Structure
- `call-graph` -> tests about how we build our call graph for reachability analysis
- `placement` -> tests about how doc comments are detected throughout code
- ``