# PusyuuPush 連携仕様書

version: 2.0 / 最終更新: 2026-09-12

## 0. 3つの通知チャンネル(まずこれを読んでください)

通知を外へ出す経路は3つあり、**違うのは「最初の一手を誰が打つか」だけ**です。

| チャンネル | 起こす人 | 中身の取り方 | 表示する人 |
|---|---|---|---|
| `push` | プッシュサービス(FCM等) | SWが `?push_inbox=1` | Service Worker |
| `desktop` | ページ自身のタイマー | ページが `?push_inbox=1` | ページ |
| `rss` | RSSリーダーの定期取得 | リーダーが `?feed=<token>` | リーダー / 閲覧ページ |

「起こす」と「中身」を分離した既存の設計(2節の空ペイロード+fetch-on-wake)が、
そのまま3つ全部に効いています。RSSリーダーは**プッシュサービスの代役**、ページの
タイマーも**プッシュサービスの代役**です。新しい概念は1つもありません。

`inbox` は「通知の実体」、チャンネルは「それをどの経路で外へ出してよいか」で、
**層が違います**。だから配送を止めるチャンネルがあっても inbox への追記は必ず
行われます(サービス自身の画面に出す未読一覧はチャンネルの話ではないため)。

`desktop` だけは「配送経路」ではありません。APIが押し出すわけではなく、ページが
自分で表示します。APIがやるのは**意思の保管**と、既にある**中身の提供**だけです。

## 0.05 どこに何を置くか(迷ったらこの表)

| | 置き場所 | 理由 |
|---|---|---|
| プッシュの購読トグル | **サービスの画面** | 許可も購読も、そのオリジンでしか出来ない |
| デスクトップ通知のトグル | **サービスの画面** | 同上 |
| RSSの使う/使わない・フィード発行 | **このAPIの `?ui=` 画面** | ブラウザ側の操作が無く、フィードURLを表示する場所が要る |
| 3チャンネルの状態の保管 | **このAPI** | 端末をまたぐ。配送のゲートに使う |
| 配送してよいかの判定 | **このAPI** | サービスが知らなくても効く |

**ブラウザの通知許可は、呼んだページのオリジンにしか効きません。** サービスは
`p-chat.pusyuuwanko.com` のような別オリジンなので、この画面でプッシュやデスクトップの
スイッチを持っても、押して実際に効かせることができません。加えて**ブラウザは、利用者の
操作を伴わない許可要求を自動的に拒否します**(「対話がないため自動的にブロックしました」)。
つまり許可は「押した場所」でしか取れず、スイッチと許可は離せません。

だからプッシュとデスクトップのトグルはサービス自身の画面に置き、その裏で
`?api=channels_set` を呼びます。`push_subscribe` と同じ形(JS → 自分のPHP →
サーバー間で通知API)です。

## 0.1 「サービスが知らなくても成り立つ」ということ

このAPIの追加機能は、**呼び出し側が何も知らなくても正しく動きます。**

- チャンネルの判定は `send` / `subscribe` / `feed_create` の**内側**で自動的に効く。
  サービスが `channels_get` を呼ばなくても、「使わない」と言った利用者のところへは
  配送されない。
- RSSフィードの配信URL・暗号化フィードの閲覧ページ・**RSS設定画面**は、すべて
  `pusyuu_push/index.php` 自身が公開ルートとして持っている。サービス側に `?feed=`
  の受け口を作る必要はない。
- **既存のサービスは1行も変えなくてよい。** `send` の応答に `channels` が増え、
  `inbox` に省略可能な `channel` が増えただけで、従来の呼び出しは従来どおり動く。

逆に、**サービスが自分で持たなければならないもの**もあります(0.05節)。プッシュと
デスクトップ通知のトグルは、ブラウザの制約でサービスの画面にしか置けません。
このAPIが肩代わりできるのは「状態を預かること」と「配送を止めること」までです。

唯一サービスにしか出来ないのは「ブラウザの前にいる利用者が誰なのかを保証すること」
です。このAPIは `service` と `userid` という不透明な文字列しか知らず、ブラウザとの
セッションを持たないため、本人確認を自力では行えません。`?api=settings_ticket` は
**その一点だけをサービスから借りる仕組み**で、サービスがすべきことはこれで得た
URLへリンクを1本張ることだけです(6節)。

## 1. これは何か

全サービス共通の**プッシュ通知バックエンド**です。ブラウザ/タブを閉じていても、OSのプッシュ
サービス(Chrome→FCM、Firefox→Mozilla Push等)経由でService Workerを起こし、通知を表示させる
ことができます。`p-meikiee/ACCOUNTS_INTEGRATION_SPEC.md` と同じ考え方で、入口を
`main/pusyuusystem/apis/pusyuu_push/index.php` 1ファイルに統合しています。

`service`(自分のサービス名。例: `p-chat`)と `userid`(通知を届けたい相手のID)は、呼び出し側が
自由に決める**不透明な文字列**です。accountsのuseridハッシュである必要はなく、匿名actorの
IDのような各サービス固有の識別子でも構いません。このAPI自身は中身が何を意味するか一切
関知しません(4.1節の汎用データストアと同じ設計思想です)。

## 2. なぜ「中身の無い(empty payload)プッシュ」なのか

Web Pushの本来の仕様(RFC 8291)では、通知のタイトルや本文をサーバ→ブラウザ間で暗号化して
運びます。これにはECDH共有鍵の導出が必要で、PHPでは `openssl_pkey_derive()` を使いますが、
**この関数はPHP 8.1以降でしか使えません**。このサーバのPHPが8.0の可能性がある
(`pusyuu_memo` 時代からの既知の注意点)ため、生PHPでの楕円曲線演算の自前実装は避け、
以下の設計にしています。

1. サーバは**中身の無い**プッシュだけをブラウザへ送る(VAPIDでの送信元認証はする。ES256の
   JWT署名は `openssl_sign()` だけで完結し、鍵導出は不要)。
2. ブラウザのService Workerは `push` イベントを受けたら、**自分自身のオリジン**へ
   `fetch()` する(同一オリジンなのでセッションCookieがそのまま乗る)。
3. そのfetch先(呼び出し側サービス自身のPHP)が、このAPIの `?api=inbox` を(サーバ間・
   合言葉付きで)呼んで実際の通知内容を取得し、JSONで返す。
4. Service Workerがその内容で `showNotification()` する。

通知の「意味」(誰が何を送ったか)は完全に呼び出し側サービスの責務で、このAPIは
「起こす」「未読を一時的に預かる」ことだけを担当します。

## 3. 新しいサービスを繋ぐ手順

### 3.1 サーバ側(PHPクライアント関数をコピーする)

`accounts` 連携と同じ「別ファイルに切り出さず、自分の `index.php` へ直接書き込む」方式です。
以下を自分のサービスの入口ファイルへコピーしてください(`p-chat/index.php` に実装例があります)。

```php
if (!defined('PUSYUU_PUSH_API')) {
  define('PUSYUU_PUSH_API', 'http://127.0.0.1/pusyuusystem/apis/pusyuu_push/index.php');
}
if (!defined('PUSYUU_PUSH_HOST')) {
  define('PUSYUU_PUSH_HOST', 'pusyuuwanko.com');
}

/** accountsと同じ鍵ファイルからHMACで導出する合言葉。 */
function pusyuuPushApiSecret(): string {
  static $resolved = false;
  static $secret = '';
  if ($resolved) { return $secret; }
  $resolved = true;

  $dir = __DIR__;
  for ($i = 0; $i <= 8; $i++) {
    $candidate = $dir . '/.pusyuuHiddenFiles/common/pusyuu_shared_key.php';
    if (file_exists($candidate)) {
      $encoded = require $candidate;
      $key = is_string($encoded) ? base64_decode($encoded, true) : false;
      if ($key !== false && strlen($key) === 32) {
        $secret = hash_hmac('sha256', 'pusyuu_push_api', $key);
      }
      break;
    }
    $parent = dirname($dir);
    if ($parent === $dir) { break; }
    $dir = $parent;
  }
  return $secret;
}

function pusyuuPushApi(string $action, array $params = []) {
  $params['api_secret'] = pusyuuPushApiSecret();
  $body = http_build_query($params);
  $url = PUSYUU_PUSH_API . '?api=' . urlencode($action);

  $raw = null;
  if (ini_get('allow_url_fopen')) {
    $context = stream_context_create(['http' => [
      'method' => 'POST',
      'header' => "Content-Type: application/x-www-form-urlencoded\r\nHost: " . PUSYUU_PUSH_HOST . "\r\n",
      'content' => $body, 'timeout' => 5, 'ignore_errors' => true,
    ]]);
    $raw = @file_get_contents($url, false, $context);
  }
  if ($raw === false || $raw === null) {
    if (function_exists('curl_init')) {
      $ch = curl_init($url);
      curl_setopt($ch, CURLOPT_POST, true);
      curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
      curl_setopt($ch, CURLOPT_HTTPHEADER, ['Host: ' . PUSYUU_PUSH_HOST]);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($ch, CURLOPT_TIMEOUT, 5);
      $raw = curl_exec($ch);
      curl_close($ch);
    }
  }
  if ($raw === false || $raw === null || $raw === '') {
    return ['ok' => false, 'error' => 'api_unreachable'];
  }
  $decoded = json_decode($raw, true);
  return is_array($decoded) ? $decoded : ['ok' => false, 'error' => 'api_broken_response'];
}

/** 便利ラッパー。これが「関数の引数を渡すだけ」で送信する本体です。 */
function pusyuuPushSend(string $service, string $userid, string $title, string $body, string $url = '', ?string $tag = null): array {
  return pusyuuPushApi('send', [
    'service' => $service, 'userid' => $userid, 'title' => $title,
    'body' => $body, 'url' => $url, 'tag' => $tag ?? '',
  ]);
}
```

`PUSYUU_PUSH_API`/`PUSYUU_PUSH_HOST` の考え方は `p-memo/index.php` の `pmemoApi()` と同じで、
接続先は `127.0.0.1` 固定、名前ベースバーチャルホストの振り分けはHostヘッダで行います。

### 3.2 ページ描画時にVAPID公開鍵を埋め込む

購読(`pushManager.subscribe()`)にはVAPID公開鍵が必要です。ブラウザから直接このAPIを
叩かせず、**自分のサービスのPHPがサーバ間で取得してページに埋め込む**でください
(`pusyuuPushApi('vapid_public_key')`)。p-chatでは既存の `data-*` 属性方式に倣い、購読ボタンの
要素に `data-vapid-key="..."` として埋め込んでいます。

### 3.3 クライアント側

1. `<script src="https://pusyuuwanko.com/pusyuusystem/scripts/push-subscribe.js"></script>` を
   読み込む(`window.PusyuuPush` が使えるようになります)。
2. 自分のサービス専用の Service Worker ファイルを1つ用意する(**別オリジンのSWは登録できない
   ため、共有はできません**。内容はどのサービスでも下のテンプレートのままで構いません)。

```js
self.addEventListener('push', (event) => {
  event.waitUntil(
    fetch('./?push_inbox=1', { credentials: 'same-origin' })
      .then((r) => r.json())
      .then((data) => Promise.all((data.items || []).map((n) =>
        self.registration.showNotification(n.title, { body: n.body, tag: n.tag || undefined, icon: n.icon || undefined, data: { url: n.url || './' } })
      )))
      .catch(() => {})
  );
});
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || './';
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then((list) => {
      for (const c of list) { if ('focus' in c) return c.focus(); }
      return clients.openWindow(url);
    })
  );
});
```

3. 購読ボタンから `PusyuuPush.subscribe({ swUrl, publicKey, subscribeUrl, extraFields })` を呼ぶ
   (`extraFields` にCSRFトークン等を含める)。`subscribeUrl` は**自分のサービス自身**の
   POSTアクション(例: `action=push_subscribe`)で、受け取った `subscription` をそのまま
   `pusyuuPushApi('subscribe', ['service'=>..., 'userid'=>..., 'subscription'=>$_POST['subscription']])`
   へ渡すだけです。

### 3.4 通知を送る

サーバ側の好きなタイミング(例: メッセージ送信成功直後)で
`pusyuuPushSend('p-chat', $recipientUserId, $title, $body, $url)` を呼ぶだけです。
**失敗しても例外を投げないため、本処理(メッセージ送信そのもの)を巻き込みません。**

### 3.5 `?push_inbox=1` の受け口を用意する

Service Workerが `push` イベントで叩く、自分自身のGETエンドポイントです。通常のページ描画
より前に処理してください(p-memoの `?download=` と同じ「特殊GETパラメータの早期分岐」
パターン)。

```php
if (isset($_GET['push_inbox'])) {
  header('Content-Type: application/json; charset=utf-8');
  $actor = /* 現在のセッションから利用者を解決する、既存のログイン確認関数 */;
  echo json_encode(pusyuuPushApi('inbox', ['service' => 'p-chat', 'userid' => $actor['userid']]));
  exit;
}
```

## 4. APIリファレンス (`pusyuu_push/index.php?api=<action>`)

すべて `POST`(フォームエンコード or JSON body)。`api_secret` は全アクション必須です。
応答は共通して `{"ok": true/false, ...}` のJSON。

| ?api= | 主なパラメータ | 説明 |
|---|---|---|
| `selftest` | なし | VAPID鍵・ストレージの疎通確認 |
| `vapid_public_key` | なし | VAPID公開鍵(base64url)を返す |
| `subscribe` | service, userid, subscription(JSON文字列), ua | 購読を保存(同じendpointならupsert) |
| `unsubscribe` | service, userid, endpoint | 購読を削除 |
| `send` | service, userid, title, body, url, tag, icon | inboxへ追記し、`push`が許可されていれば該当購読へ空ペイロードのプッシュを送信。応答に `channels` が付く |
| `broadcast` | service, title, body, url, tag, icon | **宛先が1人に決まらない通知**。そのサービスで購読かフィードを持つ人全員へ配る(8節) |
| `inbox` | service, userid, **channel(省略可)** | 未読通知一覧を返す。`channel` を指定するとそのチャンネルのゲートがかかる |
| `ack` | service, userid, ids(配列。省略時は全件) | 既読化(**削除ではなく `acked` に時刻を書く**) |
| `channels_get` | service, userid | 3チャンネルの状態・購読数・フィード数・変更履歴 |
| `channels_set` | service, userid, channel, state, purge | 状態を書き換える。`purge=1` で実体も片付ける |
| `settings_ticket` | service, userid | 通知設定画面へのURL(短命)を返す |
| `feed_create` | service, userid, mode | フィードを発行。`feed_url` と `view_url` を返す |
| `feed_list` | service, userid | 発行済みフィード(トークンは返らない) |
| `feed_revoke` | service, userid, feed_id | 失効 |

`subscription` は `PushSubscription.toJSON()` の結果(`{endpoint, keys:{p256dh, auth}}`)を
そのままJSON文字列化したものを渡してください。

`channel` は `push` / `rss` / `desktop`、`state` は `unset` / `allow` / `deny` です。

## 4.1 チャンネルの3つの状態

- `unset` … まだ何も言っていない。配送は通る
- `allow` … 明示的に許可した。配送は通る
- `deny` … **錠**。新規登録(`subscribe` / `feed_create`)を403で拒否し、既存の購読・
  フィードがあっても配送しない。発行済みのフィードURLは410を返す

**真偽値にしていない理由**: 「まだ聞いていない」と「本人が断った」を同じ `false` に
潰すと、あとから既定値を変えたくなったときに**断った人の意思まで一緒に書き換わり
ます**。3状態なら既定をどう動かしても `deny` だけは絶対に動きません。

`unset` と `allow` は配送上まったく同じです。購読ボタンやフィード発行ボタンを押す
行為そのものが意思表示なので、その上でもう一度同意を取るのは冗長だからです。
`allow` が意味を持つのは画面表示と変更履歴だけです。

**正直な限界**: `deny` は**悪意あるサービスからの防御にはなりません**。サービスは
合言葉を持っているので、自分で `channels_set` を呼んで `allow` に戻せてしまいます。
これが防ぐのは**サービス側のバグ・誤操作・仕様変更**です。そのかわり `channels_get`
が直近の変更履歴(いつ・どのチャンネルが・何経由で変わったか)を返すので、身に
覚えのない変更に**気づくこと**はできます。防止ではなく発見、という割り切りです。

## 5. プッシュが使えない環境向けのRSSフォールバック

### 5.1 まず構造的な限界

「RSSリーダーの画面に本文が出る。でもリーダー事業者には読めない」は**原理的に
作れません**。リーダーは取得したXMLをそのまま表示するソフトで、表示できるという
ことは平文を持っているということです。JSはどのリーダーも除去します。

そこでモードは「**あなたはRSSリーダーをどれくらい信用しているか**」の表明にして
あります。

| モード | リーダーに見えるもの | 向く相手 |
|---|---|---|
| `open` | 通知の本文そのもの | 手元で動くリーダー(Thunderbird、自宅のFreshRSS等) |
| `notice`(既定) | 「新着がある」ことと時刻だけ | Feedly/Inoreader等のクラウドリーダー |
| `sealed` | 読めない暗号文 | 中身も残したいが、リーダー事業者には預けたくないとき |

`sealed` は `notice` の上位互換では**ありません**。リーダーの画面には結局読めない
塊しか出ないので、見え方はほぼ同じです。`sealed` が勝つのは1点だけ
──**サービスにログインしていない環境でも、鍵さえ持っていれば中身が読める**。
ログイン済みの常用ブラウザなら `notice` のリンクを踏むだけで済むので、既定は
`notice` です。

### 5.2 URLを2つに割る、というのが設計の肝

- **購読URL** `?feed=<token>` … RSSリーダーに貼る。暗号文しか得られない
- **閲覧URL** `?view=1#t=<token>&k=<鍵>` … 自分がブックマークする。鍵はここだけ

鍵は必ずフラグメント(`#` 以降)に置きます。**フラグメントはブラウザからサーバへ
送信されない**ため、アクセスログにも中継にも残りません。

> **破ってはいけない不変条件**: フィードのXML/JSONの中に鍵を絶対に入れないこと。
> アイテムのリンクに付けてよいのは `?view=1#t=<token>` までで、`&k=` を足しては
> いけません。破るとRSSリーダーが鍵を手に入れ、`sealed` の意味が完全に消えます。
> (`token` の方はリーダーが元から持っている値なので、フィードに現れても新しい
> 漏洩にはなりません)

**鍵をサーバが持つことについて**: `sealed` の鍵はサーバ側で生成し保存します。E2E
にはなりませんが、ここでE2Eを目指すのは無意味です。通知の平文を作っているのは
サーバ自身(inbox)なので、鍵をクライアント生成にしてもサーバは元から平文を持って
います。守る相手はRSSリーダー事業者とURLを拾った第三者であって、サーバではありません。

### 5.3 実装上の落とし穴(触るときは必ず読むこと)

1. **WebCryptoと認証タグの位置が違う。** PHPの保存形式は `IV(12) + TAG(16) + 暗号文`
   の順ですが、`crypto.subtle.decrypt()` は**暗号文の末尾にタグが付いている**ことを
   期待します。閲覧ページのJSはここで並べ替えています。忘れるとエラーメッセージも
   出ないまま必ず失敗するので、「復号だけ通らない」ときは真っ先にここを疑ってください。
2. **XMLに置けない制御文字を先に落とす。** 通知本文に制御文字が1個混ざるだけで、
   リーダー側は**フィード全体を**パースエラーにします(1件だけ壊れるのではありません)。
3. **レート制限は429ではなく304。** 429を繰り返し受けると購読を自動解除するリーダー
   実装があります。また、レート制限で304を返したときに `last_poll` を更新しては
   いけません(制限窓がスライドし続け、永久に中身が返らなくなります)。
4. **`<link rel="alternate" type="application/rss+xml">` をHTMLに書かないこと。**
   書くとブラウザや拡張がフィードURLを自動発見し、秘密のURLが拡散します。

## 6. 通知設定画面(サービス側の作業はこれだけ)

`?api=settings_ticket` に `service` と `userid` を渡すと、短命(既定30分)のURLが
返ります。**そこへリンクを1本張れば終わりです。** チャンネルの切り替えもフィードの
発行・失効も、このAPIが持っている画面の中で完結します(JSは使っていません。全部
ただのPOSTフォームです)。

```php
if ($actor !== null) {
  $res = pusyuuPushApi('settings_ticket', ['service' => 'p-chat', 'userid' => $actor['userid']]);
  if (!empty($res['url'])) {
    echo '<a class="small-button" href="' . pchatH($res['url']) . '">通知設定</a>';
  }
}
```

### 6.0 チケットは一度きり(重要)

`?ui=<ticket>` に最初にアクセスした時点で、チケットは**使用済みになり、Cookieへ
引き換えられて、URLから消えます**(`?ui=1` へリダイレクトします)。

**なぜそうするか**: チケットはURLに載る資格情報で、アドレスバー・ブラウザ履歴・
アクセスログ・肩越しの視線に残ります。署名と期限だけで通すと、**そのURLを知っている
人は誰でも、別のブラウザやプライベートウィンドウから設定画面を開けてしまいます。**
そこからRSSフィードを発行されると、期限が切れたあとも通知の中身が持ち出され続けます。

一度きりにすることで、履歴やログに残るのは**既に無効になった文字列**だけになります。
Cookieは httpOnly / SameSite=Lax / このAPIのディレクトリ配下限定 / 30分です。

副作用として、**引き換えに失敗するとやり直しになります**(ブラウザがCookieを拒否
している場合など)。その場合はサービスの画面からもう一度開き直してください。

### 6.1 `return_url` を渡す(推奨)

`settings_ticket` に自分の公開URL(http(s)の絶対URL)を `return_url` として渡すと、
2つ効きます。

RSS設定画面に「サービスに戻る」リンクが出ます。渡さなくても画面は動きます。

### 6.2 設定画面の見出しは「設定値」ではなく「事実」を出す

RSSは「使う」にしていても、フィードを1本も発行していなければ何も届きません。
そのため見出しには、設定値ではなく**検証できる事実**を出します。

| 状態 | 見出しに出るもの |
|---|---|
| 使わない(錠) | `使わない` |
| 使う + フィードあり | `配信中(N本)` |
| 使う + フィードなし | `フィード未発行` |

設定値(`allow`)は「使ってよい」しか意味しません。それを「使う」と表示すると、
何も届かない状態を「使う」と言うことになり、画面が嘘をつきます。

チケットは署名だけで成立しており、サーバには保存されません(発行のたびの書き込みも
期限切れの掃除も不要。共有鍵を替えれば全部まとめて無効になります)。URLに載る資格
情報なのでアクセスログには残ります。短命であることが唯一の対処です。

この画面のPOSTはチケットそのものを資格情報にしているため、CSRFトークンは不要です
(攻撃者はチケットを知らないので別サイトからのPOSTが成立しない)。かわりに画面には
`Referrer-Policy: no-referrer` が付いています。

## 7. デスクトップ通知を「切れる」ようにする

ブラウザの通知許可(`Notification.permission`)は**JSから取り消せません**。そのため
従来のトグルは片道で、「一度許可したら、ここからは無効にできません」と案内するしか
ありませんでした。

分けて考えるべきものが2つ混ざっているのが原因です。

- **ブラウザの許可** … そのブラウザが通知を出す**能力**があるか。JSからは取り消せない
- **利用者の意思** … 通知を出して**ほしいか**。これは `desktop` チャンネルに保管できる

`desktop` チャンネルを見るようにすれば、**「許可済みだが意思は deny」という状態が
正常に存在でき、トグルが普通に往復します。**

トグルはサービスの画面に置きます(0.05節)。オンにしたとき、**そのクリックの中で**
`Notification.requestPermission()` を呼び(まだ許可を取っていなければ)、あわせて
`channels_set` に `allow` を書きます。オフのときは `deny` を書くだけで、ブラウザには
何もしません(何も出来ません)。

> **`requestPermission()` は必ずクリックハンドラの中から呼ぶこと。** ページ読み込み時に
> 自動で呼ぶと、ブラウザが「対話がない」として自動的に拒否し、**拒否された記録だけが
> 残って、以後は正しい手順を踏んでも求められなくなります**(利用者がブラウザのサイト
> 設定から手で戻すしかありません)。「親切に自動化」しないでください。

表示する直前には、許可とあわせて意思も確認してください
(`pusyuuPushApi('inbox', [... 'channel' => 'desktop'])` は `deny` のとき空を返すので、
inbox経由で表示しているならこれだけで済みます)。

ただし**どのチャンネルにも持ち込まない判断**があります。「開いている会話の通知は
出さない」「同じ会話の通知はまとめる」「通知音は許可と無関係に鳴らす」といった
判断はサービス固有のものなので、サービス側に残してください。このAPIは `service` と
`userid` という不透明な文字列しか知らない、という立場を崩すと、次のプロダクトを
繋ぐときに前のプロダクトの都合が邪魔をします。

## 8. ブロードキャスト(宛先が1人に決まらない通知)

`send` は `(service, userid)` 宛てですが、「お知らせを追加した」「新しいスレッドが
立った」のように相手が1人に決まらない通知もあります。それが `broadcast` です。

**宛先は「そのサービスで購読かRSSフィードを持っている人」だけ**です。どちらも自分で
ボタンを押さなければ存在しないので、これがそのまま「配ってよい相手」になります。
全利用者へ勝手に配ることにはなりません。

### 8.1 なぜ共有の擬似useridで済ませないか

「全員が同じ userid(例 `public`)を使えばよいのでは」と思うかもしれませんが、
**これは壊れます**。inbox は `ack` するまで残る設計なので、共有していると
**誰か1人が受け取って ack した瞬間に全員ぶんが既読になり、残りの人には二度と
表示されません**。だから `broadcast` は1人ずつの inbox へ同じ内容を積みます。

### 8.2 配送の締め切り

`broadcast` は呼び出し側の本処理(投稿の保存、お知らせの追加)の直後に走るため、
購読者が増えるほど配送時間がそのまま利用者の待ち時間になります。そこで
`BROADCAST_PUSH_DEADLINE_SEC`(既定5秒)を過ぎたら**プッシュ配送だけをやめます**。
inbox への追記は全員ぶん済んでいるので、届かなかった人も次にページを開いた時や
RSSで受け取れます。応答の `deferred` がその件数です。

### 8.3 いま繋がっているもの

| サービス | いつ送るか | どこにフックがあるか |
|---|---|---|
| `pips` | 新しいスレッドが立った時(**返信では送らない**) | `pips/index.php` の `PipsPostHandlers::postCreate()` |
| `main` | お知らせを1件追加した時 | `main/SystemFolder/oppai/index.php` の `oppaiAnnounceNotification()` |

どちらも**保存できたと確認できた後**にだけ送ります。保存の前や、成否を見ずに送ると
「通知は来たのに中身が無い」が起きます。また、送信に失敗しても本処理(投稿・お知らせの
追加)は成功のままにします。通知が送れないことは、投稿が失敗したことではありません。

`pips` の宛先はログイン中アカウントの userid ハッシュです。`main` にはログインが
無いため、**購読ボタンを押した時にだけ**発行する端末ごとの匿名ID(Cookie
`pusyuu_main_device`)を宛先にします。見に来ただけの人には何も置きません。

## 9. 既知の制約

- iOS Safariはホーム画面に追加した(PWAとしてインストールした)状態でないとWeb Push自体が
  動作しません(OS側の制約で、このAPIでは回避できません)。**RSSフォールバックが最も
  効くのはこの環境です。**
- **RSSの遅延は5分〜数時間。** Feedly等のクラウドリーダーは更新の少ないフィードを
  1時間以上放置します。フォールバックとして実用になるのは、5〜15分間隔に設定できる
  手元のリーダー(Thunderbird、Fluent Reader、iOSのReeder等)です。
- **リーダーが動いていないと届きません。** スマホのバックグラウンド更新設定に依存します。
- **既読がサービスへ戻りません。** リーダーは `ack` を投げられないため、RSSだけで
  受け取っている利用者の通知は保持期間切れまで未読のまま残ります。
- **メタデータは必ず漏れます。** どのサービスの通知が、いつ、どれくらいの頻度で
  来たか。`sealed` でも同じです。隠せるのは本文だけです。
- **フィードのトークンは持っているだけで使える資格情報です。** OPMLのエクスポート、
  リーダーのアカウント、ブラウザ履歴、アクセスログに残ります。失効と再発行が
  いつでも1クリックでできることが、これに対する現実的な対処です。
- inboxは1(service, userid)組あたり、未読が `INBOX_MAX_PER_USER` 件(既定50件)、
  既読を含めた履歴が `INBOX_HISTORY_MAX_PER_USER` 件(既定120件)かつ
  `INBOX_HISTORY_DAYS` 日(既定7日)まで。フィードが遡れるのはこの履歴の範囲です。
- 発行済みフィードは1利用者あたり `FEED_MAX_PER_USER` 本(既定5本)まで。
  `FEED_IDLE_EXPIRE_DAYS`(既定180日)取得が無いものは自動的に失効します。
- ペイロード無しの設計上、通知の内容は必ず「呼び出し側サービス自身の `?push_inbox=1` 相当の
  エンドポイント」から取得される前提です。このエンドポイントを用意しないサービスは、
  Service Workerが `push` イベントを受けても何も表示できません(RSSは別で、
  このAPIが直接配信するためサービス側の受け口は不要です)。
