// 既読受領証明の自動発行バッチ間隔（未受領メッセージをまとめて署名・§6.7）。
// hook と Node の回帰テストが同じ値を参照し、片側だけの変更を許さない。
export const READ_RECEIPT_BATCH_MS = 8000;
