# pusyuu_push

全サービスで共通して使えるプッシュ通知の API です。
呼び出し側が自由に決める `service` と `userid` という2つの文字列だけを手がかりに、
購読の保存・プッシュの送信・受信箱の読み出しを行います。

購読情報や受信箱などの運用データはこのリポジトリには含まれていません。

## 仕組み

- ペイロードの暗号化(RFC 8291)は行わず、**中身の無いプッシュ**だけを送ります。PHP 8.0 でも動くようにするためです
- 通知を受けた各サービスの Service Worker が、自分のサーバー経由で `?api=inbox` を読み、実際の内容を表示します
- VAPID の署名は `openssl_sign()` だけで行います
- 通知の経路(チャンネル)は `push` / `desktop` / `rss` の3つです。それぞれ利用者ごとに `unset` / `allow` / `deny` を持ちます

ブラウザ側の購読処理には [push-subscribe](https://github.com/PusyuuWanko/push-subscribe) が使えます。

## API (`?api=`)

| アクション | 内容 |
| --- | --- |
| `selftest` / `vapid_public_key` | 設置確認・VAPID 公開鍵の取得 |
| `subscribe` / `unsubscribe` | 購読の登録・解除 |
| `send` / `broadcast` | 1人へ送信・全員へ送信 |
| `inbox` / `ack` | 受信箱の読み出し・既読 |
| `channels_get` / `channels_set` | 通知経路ごとの許可状態 |
| `settings_ticket` | 利用者向けの通知設定画面への URL を発行 |
| `feed_create` / `feed_list` / `feed_revoke` | RSS フィードの発行・一覧・取り消し |

認証は、暗号化キーから導出した合言葉(api_secret)で行います。
新しいサービスを繋ぐ手順は [PUSH_INTEGRATION_SPEC.md](PUSH_INTEGRATION_SPEC.md) を参照してください。

## 必要なもの

- PHP 8.0 以上(OpenSSL 拡張)
- 公開ディレクトリの外にある非公開フォルダ(保存用の鍵・VAPID 鍵を置きます)。場所は `index.php` 冒頭の `PUSH_HIDDEN_PATH` / `PUSYUU_HIDDEN_COMMON_PATH` で指定します

## ライセンス

[MIT License](LICENSE) © 2026 ISAMI ABE
