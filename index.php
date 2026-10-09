<?php
/*****************************************
  *----------------------------------
  |  ThisScriptVersion: 1.0.0     |
  |  © 2026 By ISAMI ABE          |
  |  LastUpdate: 2026-10-08       |
  |  License: MIT License         |
  |  pusyuu_push (プッシュ通知API) |
----------------------------------*
******************************************/
/**
 * =====================================================================
 * PusyuuPush - 全サービス共通のプッシュ通知API
 * 配置場所: main/pusyuusystem/apis/pusyuu_push/index.php
 *
 * 「service」「userid」という2つの呼び出し側が自由に決める不透明な文字列だけを
 * 手がかりに、購読(subscribe)の保存・プッシュの送信(send)・受信箱の読み出し
 * (inbox)を行う、汎用のプッシュ通知バックエンドです。userid はaccountsの
 * useridハッシュである必要はなく、匿名actorのIDのような各サービス固有の
 * 識別子でも構いません。
 *
 * 【重要な設計判断】ペイロード暗号化(RFC 8291: ECDH+HKDF+AES-GCM)は実装して
 * いません。共有鍵の導出に使う openssl_pkey_derive() はPHP 8.1以降でしか
 * 使えず、このサーバのPHPが8.0の可能性がある(pusyuu_memo/index.phpの既存の
 * コメント参照)ため、生PHPでの楕円曲線演算の自前実装は避けました。
 * 代わりに「中身のない(empty payload)プッシュ」だけを送ります。呼び出し側
 * サービスのService Workerは push イベントを受けたら自分自身のオリジンへ
 * fetch()し(同一オリジンなのでブラウザのセッションCookieがそのまま乗る)、
 * このAPIの ?api=inbox を(呼び出し側サービスのPHP経由で)叩いて実際の通知
 * 内容を取得し、showNotification() します。VAPID自体の署名(ES256のJWT)は
 * openssl_sign() でのECDSA署名だけで完結するため、鍵導出(derive)は不要です。
 *
 * 認証は accounts(p-meikiee)と同じ「暗号化キーから導出した合言葉(api_secret)」
 * 方式です。IPアドレス制限は使いません(Docker等のNAT環境でREMOTE_ADDRが
 * 信用できないため。詳しくは p-meikiee/ACCOUNTS_INTEGRATION_SPEC.md 5節)。
 *
 * ---------------------------------------------------------------------
 * 【通知チャンネルという考え方】
 *
 * 通知を「外へ出す経路」は3つあり、違うのは"最初の一手を誰が打つか"だけです。
 *
 *   push    … プッシュサービス(FCM等)が起こす → SWがinboxを読む   → SWが表示
 *   desktop … ページ自身のタイマーが起こす     → ページがinboxを読む → ページが表示
 *   rss     … RSSリーダーの定期取得が起こす    → リーダーがフィードを読む
 *
 * 「起こす」と「中身」を分離した既存の設計(空ペイロード+fetch-on-wake)が、
 * そのまま3つ全部に効いています。inboxは「通知の実体」、チャンネルは「それを
 * どの経路で外へ出してよいか」で、層が違います。だから配送を止めるチャンネルが
 * あっても inbox への追記は必ず行います。
 *
 * 各チャンネルの状態は unset(まだ何も言っていない)/ allow(明示的に許可)/
 * deny(錠。新規登録を拒否し、既存のものがあっても配送しない)の3値です。
 * 真偽値にしない理由は CHANNELS_FILE 付近のコメントに書いてあります。
 *
 * ---------------------------------------------------------------------
 * 【呼び出し側サービスがこのAPIを"知らなくても"成り立つこと】
 *
 * このAPIの追加機能は、呼び出し側が何も知らなくても正しく動きます。
 *
 *  - チャンネルの判定は send / subscribe / feed_create の内側で自動的に効く。
 *    サービスが channels_get を呼ばなくても、denyの利用者へは配送されない。
 *  - RSSフィードの配信URL・暗号化フィードの閲覧ページ・通知設定画面は、
 *    すべてこのファイル自身が公開ルートとして持っている(下の「公開ルート」)。
 *    サービス側に ?feed= の受け口を作る必要はない。
 *  - サービスが1つだけ足せば利用者に設定画面を出せる、という最小の接点として
 *    ?api=settings_ticket がある。返ってきたURLへリンクを1本張るだけでよい。
 *
 * 唯一サービスにしか出来ないのは「ブラウザの前にいる利用者が誰なのかを保証する
 * こと」です。このAPIはserviceとuseridという不透明な文字列しか知らず、ブラウザと
 * セッションを持たないため、利用者本人であることを自力では確認できません。
 * settings_ticket はその一点だけをサービスから借りる仕組みです。
 *
 * 新しいサービスをこのAPIに繋ぐ手順は同ディレクトリの PUSH_INTEGRATION_SPEC.md
 * を参照してください。
 * =====================================================================
 */

declare(strict_types=1);
// =====================================================================
// 非公開フォルダの指定(CODING_STYLE 5-3)
//
// 【このプロダクトを別の場所・別のサーバへ置いたら、ここだけ書き換えてください】
// このファイルのあるフォルダからの素の相対パスです。Webで公開されない場所を指してください。
// 使う前に下の PusyuuHiddenDir::verify() が「フォルダがあって読めるか」と「公開されていないか」を
// 確かめます。確かめられなければ、そのフォルダを使う機能が止まります(公開フォルダや
// 一時フォルダへ代わりに書くことはありません)。
// =====================================================================
const PUSH_HIDDEN_PATH          = '../../../../.pusyuuHiddenFiles/pusyuu/main/pusyuu_push'; // 通知APIだけが使う(保存用の鍵・VAPID鍵)
const PUSYUU_HIDDEN_COMMON_PATH = '../../../../.pusyuuHiddenFiles/common'; // 複数プロダクトで共有(共有鍵)

// =====================================================================
// 時刻は日本時間で扱います。
//
// 【初期化より前に置くこと】PHP の既定のタイムゾーンは、素のままだと UTC です(CODING_STYLE 12-5)。
// 指定しないと、画面に出す時刻・保存する日時の文字列・「今日」の区切りが9時間ずれます。
// このプロダクトは日本の利用者向けなので、ここで日本時間に決めます。
// =====================================================================
date_default_timezone_set('Asia/Tokyo');

// =====================================================================
// PusyuuHiddenDir - 非公開フォルダの確かめ役(CODING_STYLE 5-3)
//
// 【全プロダクトに同じ物をコピーして配っています。プロダクト固有の事情を入れないこと】
// 直すときは1つ直して、他のプロダクトへそのまま貼り直してください。
//
// 入口の定数に書いた非公開フォルダのパスを、使う前に1回だけ確かめます。
//   1. フォルダとして存在し、読めること(ファイルではなくフォルダで判断します)
//   2. サーバが公開している範囲の内側でないこと
//   3. 逆に、公開範囲が非公開フォルダの中に入っていないこと(上の階層を指す指定ミス)
//   4. 公開範囲の手がかりが1つも取れなければ使わない(非公開だと確かめられないため)
// 確かめられたら実際の場所(realpath の絶対パス)、確かめられなければ null を返し、
// 理由を error_log に残します。
//
// 【公開範囲は、取れた手がかりを全部使うこと】特定のHTTPサーバの機能に頼らないためです。
//   DOCUMENT_ROOT         … PHPを動かすサーバが渡す値(CGI / FastCGI の慣習)
//   CONTEXT_DOCUMENT_ROOT … Apache だけが渡す値。無ければ使わないだけ
//   SCRIPT_FILENAME から SCRIPT_NAME を末尾で除いたもの … どのサーバでも必ずある値から求めた、
//                           このリクエストの実際の公開元(nginx の alias などでも正しく出る)
// .htaccess や Require all denied は判断の根拠にしません(nginx などは読みません)。
//
// 【null のときに別の場所へ書かないこと】公開フォルダや一時フォルダへ代わりに書くと、
// 鍵が公開される事故になります。呼び出し側は null を「使えない」として機能を止めてください。
// =====================================================================
if (!class_exists('PusyuuHiddenDir')) {
  final class PusyuuHiddenDir {
    public static function verify(string $path): ?string {
      $real = ($path === '') ? false : realpath($path);
      $published = self::publishedRoots();
      $result = null;

      if ($real === false || !is_dir($real)) {
        error_log('[PusyuuHiddenDir] 非公開フォルダが見つかりません: ' . $path);
      } else if (!is_readable($real)) {
        error_log('[PusyuuHiddenDir] 非公開フォルダを読めません: ' . $path . ' (' . $real . ')');
      } else if ($published === []) {
        error_log('[PusyuuHiddenDir] サーバが公開している範囲が分からないため、非公開だと確かめられません。使いません: ' . $real);
      } else if (self::overlaps($real, $published)) {
        error_log('[PusyuuHiddenDir] 非公開フォルダが、Webで公開されている範囲と重なっています。使いません: ' . $real
          . ' / 公開範囲=' . implode(', ', $published));
      } else {
        $result = $real;
      }

      return $result;
    }

    /** 今のリクエストでサーバが公開している場所(実在するものだけ、realpath済み)。 */
    private static function publishedRoots(): array {
      $candidates = [
        (string)($_SERVER['DOCUMENT_ROOT'] ?? ''),
        (string)($_SERVER['CONTEXT_DOCUMENT_ROOT'] ?? ''),
        self::rootFromScript(),
      ];
      $roots = [];

      foreach ($candidates as $candidate) {
        $real = ($candidate === '') ? false : realpath($candidate);
        if ($real !== false && is_dir($real) && !in_array($real, $roots, true)) {
          $roots[] = $real;
        }
      }

      return $roots;
    }

    /**
     * SCRIPT_FILENAME(実ファイル)の末尾から SCRIPT_NAME(URL上のパス)を取り除いた場所。
     * 末尾が一致しない(書き換えで別のファイルが動いている等)ときは空文字。
     */
    private static function rootFromScript(): string {
      $file = str_replace('\\', '/', (string)($_SERVER['SCRIPT_FILENAME'] ?? ''));
      $name = (string)($_SERVER['SCRIPT_NAME'] ?? '');
      $tail = substr($file, -strlen($name));
      $root = '';

      if ($file !== '' && $name !== '' && $name[0] === '/' && $tail === $name) {
        $root = substr($file, 0, strlen($file) - strlen($name));
        $root = ($root === '') ? '/' : $root;
      }

      return $root;
    }

    /** 片方がもう片方の中(同じ場所を含む)にあるか。 */
    private static function overlaps(string $dir, array $roots): bool {
      $target = rtrim(str_replace('\\', '/', $dir), '/') . '/';
      $result = false;

      foreach ($roots as $root) {
        $prefix = rtrim(str_replace('\\', '/', $root), '/') . '/';
        if (strncmp($target, $prefix, strlen($prefix)) === 0 || strncmp($prefix, $target, strlen($target)) === 0) {
          $result = true;
        }
      }

      return $result;
    }
  }
}

// 確かめた結果(実際の場所の絶対パス、確かめられなければ null)。共有スクリプトへはこの定数で渡します。
// 【共有スクリプトを読み込むより前に置くこと】読み込んだ時点で定数を見るものがあります。
define('PUSH_HIDDEN_DIR', PusyuuHiddenDir::verify(PUSH_HIDDEN_PATH));
define('PUSYUU_HIDDEN_COMMON_DIR', PusyuuHiddenDir::verify(PUSYUU_HIDDEN_COMMON_PATH));


/**
 * 購読データの暗号化ヘルパー。このAPI自身が持つ、これが唯一の実装。
 *
 * 【なぜ共有スクリプトを使わないか】以前は
 * main/pusyuusystem/scripts/php_scripts/pusyuu_storage_crypto.php をrequireしていたが、
 * 共有する意味が実は無かった: この形式で書いたファイルを読むのは書いた本人
 * (=このpusyuu_push)だけで、他のプロダクトは自分専用の鍵で自分のファイルを
 * 読み書きしている。互いのファイルを読む場面が存在しないので、形式を共有しても
 * 得る物が無い一方、共有ファイルが1つ消えるだけで動かなくなる依存だけが残る。
 * 各プロダクトが自分の実装を1つ持つ方針へ揃えたため、共有版は削除済み。
 *
 * 【変更してはいけないこと】保存形式は base64( IV 12バイト + TAG 16バイト + 暗号文 )。
 * 変えると既存の購読データが読めなくなる。
 */
function pusyuuPushAesGcmEncrypt(string $plaintext, string $rawKey): ?string {
  $iv = random_bytes(12);
  $tag = '';
  $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $rawKey, OPENSSL_RAW_DATA, $iv, $tag);

  if ($cipher === false) {
    $encoded = null;
  } else {
    // 【この並び順を変えないこと】IV 12バイト + TAG 16バイト + 暗号文。
    // 変えると既存の購読データが1件も読めなくなります。
    $encoded = base64_encode($iv . $tag . $cipher);
  }

  return $encoded;
}

function pusyuuPushAesGcmDecrypt(string $encoded, string $rawKey): ?string {
  $raw = base64_decode($encoded, true);

  // 28バイト未満は、IVとTAGだけでも足りない = そもそもこの形式ではありません。
  if ($raw === false || strlen($raw) < 28) {
    $plain = null;
  } else {
    $iv     = substr($raw, 0, 12);
    $tag    = substr($raw, 12, 16);
    $cipher = substr($raw, 28);
    $opened = openssl_decrypt($cipher, 'aes-256-gcm', $rawKey, OPENSSL_RAW_DATA, $iv, $tag);
    $plain = ($opened === false) ? null : $opened;
  }

  return $plain;
}

/** 鍵ファイルが有れば読み込み、無ければ生成して保存する。戻り値は生バイト列(32byte)。 */
function pusyuuPushLoadOrCreateKey(string $keyFilePath): ?string {
  if (is_file($keyFilePath)) {
    $encoded = require $keyFilePath;
    $decoded = is_string($encoded) ? base64_decode($encoded, true) : false;
    // 長さが違う鍵をそのまま使うと、暗号化はできても復号だけ失敗します。ここで弾きます。
    $key = ($decoded !== false && strlen($decoded) === 32) ? $decoded : null;
  } else {
    $raw = random_bytes(32);
    $php = "<?php\nreturn '" . base64_encode($raw) . "';\n";

    if (@file_put_contents($keyFilePath, $php) === false) {
      $key = null;
    } else {
      @chmod($keyFilePath, 0600);
      $key = $raw;
    }
  }

  return $key;
}

/** 行の配列をJSONLとして連結し、まとめて暗号化して保存する(tmp+rename方式)。 */
function pusyuuPushWriteEncryptedJsonlBlob(string $file, array $rows, string $rawKey): bool {
  $lines = [];
  foreach ($rows as $row) {
    $lines[] = json_encode($row, JSON_UNESCAPED_UNICODE);
  }

  $encrypted = pusyuuPushAesGcmEncrypt(implode("\n", $lines), $rawKey);
  $dir = dirname($file);

  if ($encrypted === null) {
    $ok = false;
  } else if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
    // mkdir が失敗しても、他のリクエストが同時に作っていれば is_dir は真になります。
    // だから「作れなかった」だけでは失敗にせず、最後にもう一度確かめます。
    $ok = false;
  } else {
    // いったん別名で書いてから rename します。途中で落ちても、読み手が
    // 半分だけ書かれたファイルを掴むことがありません(rename は不可分)。
    $tmp = $dir . '/.' . basename($file) . '.' . bin2hex(random_bytes(6)) . '.tmp';

    if (@file_put_contents($tmp, $encrypted) === false) {
      $ok = false;
    } else if (!@rename($tmp, $file)) {
      @unlink($tmp);
      $ok = false;
    } else {
      $ok = true;
    }
  }

  return $ok;
}

// Content-Typeはここでは決めない。このファイルはJSON以外に、RSS(XML)・
// 閲覧ページ(HTML)・通知設定画面(HTML)も返すようになったため、ヘッダは
// それぞれの出口で送る(下の「公開ルート」とJSON用APIの入口を参照)。

// =====================================================================
// ▼▼▼ 設定エリア ▼▼▼
// =====================================================================

// ディレクトリ名は.htaccessに依存せず推測不能なランダム名にして隠蔽し、
// 中身(購読エンドポイント・鍵、通知本文)もAES-256-GCMで暗号化して保存する。
const STORAGE_DIR         = __DIR__ . '/1ef71e518ba544e49351fdeca1d01fab';
const SUBSCRIPTIONS_FILE  = STORAGE_DIR . '/subscriptions.jsonl';
const INBOX_FILE          = STORAGE_DIR . '/inbox.jsonl';
const CHANNELS_FILE       = STORAGE_DIR . '/channels.jsonl';
const FEEDS_FILE          = STORAGE_DIR . '/feeds.jsonl';
const STORAGE_KEY_FILE_NAME = 'pusyuu_push_storage_key.php';

// 合言葉の導出に使う既存の共有鍵ファイル(accounts等と同じもの)。置き場は共有の非公開フォルダ
// (PUSYUU_HIDDEN_COMMON_DIR)です。
const SHARED_KEY_FILE_NAME = 'pusyuu_shared_key.php';

// VAPID鍵ペアの保存先ファイル名(通知API専用の非公開フォルダ PUSH_HIDDEN_DIR の中)。無ければ初回アクセス時に生成します。
const VAPID_KEY_FILE_NAME = 'pusyuu_push_vapid.php';
const VAPID_SUBJECT       = 'mailto:information@pusyuuwanko.com';

// 1件のプッシュ配送リクエストのタイムアウト・保持期間(秒)。
// 中身が無い「起こすだけ」のプッシュなので、長く保持させる意味は薄い。
const PUSH_HTTP_TIMEOUT = 8;
const PUSH_TTL          = 60;

// 1(service, userid)組あたりに溜めておく未読通知の上限。超えた分は古い順に捨てる。
const INBOX_MAX_PER_USER = 50;

// ブロードキャスト(宛先が特定の1人ではない通知)でプッシュ配送に使ってよい秒数。
//
// 【なぜ締め切りを設けるか】ブロードキャストは呼び出し側の本処理(PIPSなら投稿の
// 保存、mainならお知らせの追加)の直後に走る。購読者が増えるほど配送先が増え、
// 1件ずつHTTPで送る時間がそのまま利用者の待ち時間になる。締め切りを過ぎたら
// プッシュ配送だけをやめる。inboxへの追記は全員ぶん済んでいるので、届かなかった
// 人も次にページを開いた時やRSSで受け取れる。
const BROADCAST_PUSH_DEADLINE_SEC = 5;

// 既読になった通知も、RSSフィードが読む履歴としてしばらく残しておく。
//
// 【なぜ既読を即削除しないのか】RSSリーダーは ack を投げられない(ただGETする
// だけの相手)ので、フィードから読むぶんには通知が永久に未読のまま残る。一方で
// プッシュ側が ack した瞬間に行が消えると、フィードの履歴が歯抜けになる。
// そこで ack は「削除」ではなく「acked に時刻を書く」へ変え、未読一覧
// (inboxFor)は acked の無い行だけを返すようにした。この変更で既存の挙動は
// 完全に維持される(既存データに acked キーは無い = 全部未読と解釈される)。
// 代償としてファイルが太るため、その唯一の出口が下の2つの上限になる。
// ここを緩めるとファイルが際限なく育つので、触るときは理由を添えること。
const INBOX_HISTORY_MAX_PER_USER = 120;
const INBOX_HISTORY_DAYS         = 7;

// ---------------------------------------------------------------------
// 通知チャンネル
// ---------------------------------------------------------------------

const CHANNEL_PUSH    = 'push';
const CHANNEL_RSS     = 'rss';
const CHANNEL_DESKTOP = 'desktop';
const CHANNEL_ALL     = [CHANNEL_PUSH, CHANNEL_RSS, CHANNEL_DESKTOP];

// 【なぜ真偽値ではなく3状態か】「まだ何も言っていない(unset)」と「本人が
// 断った(deny)」を同じ false に潰すと、あとからこの既定値を変えたくなった
// とき、断った人の意思まで一緒に書き換わってしまう。3状態にしておけば既定を
// どう動かしても deny だけは絶対に動かない。
// unset と allow は配送の挙動としては同じ(登録操作そのものが意思表示なので、
// その上でもう一度同意を取るのは冗長)。allow が意味を持つのは画面表示と監査。
const CHANNEL_UNSET = 'unset';
const CHANNEL_ALLOW = 'allow';
const CHANNEL_DENY  = 'deny';

// 「身に覚えのない変更」に利用者が気づけるよう、直近の変更履歴を何件残すか。
// deny はサービス自身が allow へ戻せてしまう(サービスは合言葉を持っている)ため、
// 防止はできない。できるのは発見だけ、という割り切り。
const CHANNEL_AUDIT_MAX = 5;

// ---------------------------------------------------------------------
// RSSフィード
// ---------------------------------------------------------------------

// モードは「あなたはRSSリーダーをどれくらい信用しているか」の表明。
//   open   … 本文をそのまま載せる。手元のリーダー(Thunderbird等)向け
//   notice … 「新着がある」ことだけ載せる。クラウドのリーダーでも中身が漏れない
//   sealed … 本文を暗号化して載せる。鍵を持つ閲覧ページだけが読める
const FEED_MODE_OPEN    = 'open';
const FEED_MODE_NOTICE  = 'notice';
const FEED_MODE_SEALED  = 'sealed';
const FEED_MODE_ALL     = [FEED_MODE_OPEN, FEED_MODE_NOTICE, FEED_MODE_SEALED];
const FEED_MODE_DEFAULT = FEED_MODE_NOTICE;

// 1本のフィードに載せる最大件数と、1利用者が持てるフィードの本数。
const FEED_ITEM_MAX     = 30;
const FEED_MAX_PER_USER = 5;

// 同じフィードへの取得が短い間隔で連続したときに 304 で返す間隔(秒)。
// 429 ではなく 304 にするのは、429 を繰り返し受けると購読を自動解除する
// リーダー実装があるため。304 なら正常動作と解釈される。
const FEED_MIN_POLL_SEC = 60;

// 一度も取りに来られないまま放置されたフィードを自動で失効させる日数。
const FEED_IDLE_EXPIRE_DAYS = 180;

// RSS設定画面(?ui=)へ入るための一時チケットと、引き換えに渡すCookieの有効期間(秒)。
//
// 【チケットは一度きり】チケットはURLに載る資格情報で、アドレスバー・ブラウザ履歴・
// アクセスログ・肩越しの視線に残る。署名と期限だけで通してしまうと、そのURLを
// 知っている人は誰でも(別のブラウザでも、プライベートウィンドウでも)設定画面を
// 開けてしまい、そこからRSSフィードを発行されると通知の中身まで持ち出される。
// そこで最初の1回でCookieへ引き換え、チケット自体はその場で使用済みにする。
// 引き換え後はURLからチケットを消す(?ui=1へリダイレクトする)ので、履歴に残るのは
// 無効になった文字列だけになる。
const SETTINGS_TICKET_TTL  = 300;
const SETTINGS_COOKIE_NAME = 'pusyuu_push_ui';
const SETTINGS_COOKIE_TTL  = 1800;
const TICKETS_USED_FILE    = STORAGE_DIR . '/tickets_used.jsonl';

// =====================================================================
// ▲▲▲ 設定エリアここまで ▲▲▲
// =====================================================================

// ---------------------------------------------------------------------
// 応答ヘルパー
// ---------------------------------------------------------------------

function respond(bool $ok, array $payload = [], int $status = 200) {
  http_response_code($status);
  echo json_encode(array_merge(['ok' => $ok], $payload), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  exit;
}

function fail(string $error, string $message, int $status = 400) {
  respond(false, ['error' => $error, 'message' => $message], $status);
}

/**
 * 動作ログ。「通知が来ない/遅い」の原因切り分け(購読が0件なのか、送信自体が
 * 失敗しているのか、プッシュサービス側での配送が遅いだけなのか)ができるよう、
 * 誰が(service/userid)・何を・どれくらいの時間で、をPHPのエラーログへ残す。
 */
function pushLog(string $msg): void {
  error_log('[PusyuuPush] ' . $msg);
}

/** HTML用エスケープ。公開ルートが返すページで使う。 */
function h(string $s): string {
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * このAPI自身の公開URL(index.phpまで)。
 *
 * 【なぜ設定に固定値を置かないか】このファイルがサーバ上のどの深さに置かれても
 * 動くようにするため、パスは SCRIPT_NAME から取る。ホストは HTTP_HOST から取る
 * (サービスからのサーバ間呼び出しは 127.0.0.1 宛だが、仕様どおり Host ヘッダに
 * 公開ホスト名が入っているので正しい値が得られる)。
 *
 * 【なぜスキームを $_SERVER から決めないか】そのサーバ間呼び出しは平文HTTPで
 * 届くため、$_SERVER['HTTPS'] は空になる。しかし利用者に渡すURLは公開側、つまり
 * HTTPSでなければならない。ここで $_SERVER を信じると http:// のURLを発行して
 * しまい、リーダーやブラウザによっては接続できない。ループバック宛でない限り
 * HTTPSとみなす、という単純な規則にしてある。
 */
function publicBaseUrl(): string {
  $host = (string)($_SERVER['HTTP_HOST'] ?? '');
  if ($host === '') { $host = (string)($_SERVER['SERVER_NAME'] ?? 'localhost'); }

  $script = (string)($_SERVER['SCRIPT_NAME'] ?? '');
  if ($script === '') { $script = '/index.php'; }

  $hostOnly = strtolower((string)strtok($host, ':'));
  if ($hostOnly === 'localhost' || $hostOnly === '127.0.0.1' || $hostOnly === '::1') {
    $scheme = 'http';
  } else {
    $scheme = 'https';
  }
  return $scheme . '://' . $host . $script;
}

// ---------------------------------------------------------------------
// 非公開フォルダ
// ---------------------------------------------------------------------

/**
 * 通知API専用の非公開フォルダ(保存用の鍵・VAPID鍵の置き場)。このファイルの先頭で確かめた
 * PUSH_HIDDEN_DIR をそのまま返し、確かめられなければ null です(CODING_STYLE 5-3)。
 * 【ここで探さないこと】以前は共有鍵のファイルを目印に上へ登って探していました。
 * 共有鍵は共有フォルダ(PUSYUU_HIDDEN_COMMON_DIR)にあり、置き場が分かれています。
 */
function pusyuuHiddenFilesDir(): ?string {
  static $warned = false;

  // 黙って null を返すと、通知が届かない理由が誰にも分からなくなります(1リクエストに1回だけ残します)。
  if (PUSH_HIDDEN_DIR === null && $warned === false) {
    $warned = true;
    error_log('[PusyuuPush] 通知API専用の非公開フォルダが使えません(詳細はPusyuuHiddenDirのログ)。');
  }

  return PUSH_HIDDEN_DIR;
}

// ---------------------------------------------------------------------
// 合言葉(api_secret)。accounts/pusyuu_memoと同じ鍵ファイルからHMACで導出する。
// ---------------------------------------------------------------------

function sharedKeyRaw(): ?string {
  static $loaded = false;
  static $key = null;

  // 2回目以降は $loaded が true なので、この塊ごと素通りして答えを使い回します。
  if ($loaded === false) {
    $loaded = true;
    $keyFile = (PUSYUU_HIDDEN_COMMON_DIR === null) ? null : PUSYUU_HIDDEN_COMMON_DIR . '/' . SHARED_KEY_FILE_NAME;
    $encoded = ($keyFile !== null && file_exists($keyFile)) ? require $keyFile : null;
    $decoded = is_string($encoded) ? base64_decode($encoded, true) : false;

    // 置き場が無い・ファイルが無い・中身が文字列でない・長さが32でない、の
    // どれか1つでも当てはまれば鍵は使えません。まとめて null にします。
    if ($decoded !== false && strlen($decoded) === 32) {
      $key = $decoded;
    } else {
      $key = null;
    }
  }

  return $key;
}

function expectedApiSecret(): ?string {
  $key = sharedKeyRaw();

  if ($key === null) {
    $secret = null;
  } else {
    $secret = hash_hmac('sha256', 'pusyuu_push_api', $key);
  }

  return $secret;
}

function requireSecret(array $input): void {
  $expected = expectedApiSecret();
  if ($expected === null) {
    fail('server_misconfigured', 'サーバ側の設定に問題があります(共有鍵ファイルを読み込めません)。', 500);
  }
  $given = inputStr($input, 'api_secret');
  if ($given === '' || !hash_equals($expected, $given)) {
    error_log('[PusyuuPush] 合言葉が一致しないリクエストを拒否しました。');
    fail('forbidden', '合言葉が一致しません。', 403);
  }
}

// ---------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------

function base64UrlEncode(string $data): string {
  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// ---------------------------------------------------------------------
// VAPID鍵ペアの生成・読み込み(p-chatの ensureChatKey() と同じ
// 「無ければ初回アクセス時に生成して保存する」方式)
// ---------------------------------------------------------------------

function vapidKeyFilePath(): ?string {
  $hidden = pusyuuHiddenFilesDir();

  if ($hidden === null) {
    $path = null;
  } else {
    $path = $hidden . '/' . VAPID_KEY_FILE_NAME;
  }

  return $path;
}

function vapidGenerateKeyPair(): ?array {
  $res = @openssl_pkey_new([
    'curve_name'       => 'prime256v1',
    'private_key_type' => OPENSSL_KEYTYPE_EC,
  ]);
  $exportedPem = '';

  if ($res === false) {
    error_log('[PusyuuPush] VAPID鍵ペアの生成に失敗しました。opensslがprime256v1に対応していない可能性があります。');
    $pair = null;

  } else if (!openssl_pkey_export($res, $exportedPem)) {
    error_log('[PusyuuPush] VAPID秘密鍵のエクスポートに失敗しました。');
    $pair = null;

  } else {
    $details = openssl_pkey_get_details($res);

    if ($details === false || !isset($details['ec']['x'], $details['ec']['y'])) {
      error_log('[PusyuuPush] VAPID公開鍵の座標を取得できませんでした。');
      $pair = null;
    } else {
      // x/yは先頭の0x00バイトが落ちて32byteに満たないことがあるため、左ゼロ埋めする。
      $x = str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT);
      $y = str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);
      $publicRaw = "\x04" . $x . $y; // 非圧縮形式の点(65byte)。ブラウザのapplicationServerKeyと同じ形式。

      $pair = [
        'private_pem'        => $exportedPem,
        'public_raw_b64url'  => base64UrlEncode($publicRaw),
      ];
    }
  }

  return $pair;
}

function vapidKeys(): ?array {
  static $loaded = false;
  static $keys = null;

  // 2回目以降は $loaded が true なので、この塊ごと素通りして答えを使い回します。
  if ($loaded === false) {
    $loaded = true;
    $path = vapidKeyFilePath();
    // 鍵ファイルを用意できたかどうか。無ければこの後の読み込みへ進みません。
    $ready = ($path !== null);

    if ($ready && !is_file($path)) {
      $generated = vapidGenerateKeyPair();
      $dir = dirname($path);

      if ($generated === null) {
        $ready = false;
      } else if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        error_log('[PusyuuPush] VAPID鍵の保存先ディレクトリを作成できません: ' . $dir);
        $ready = false;
      } else if (@file_put_contents($path, "<?php\nreturn " . var_export($generated, true) . ";\n") === false) {
        error_log("[PusyuuPush] VAPID鍵ファイルを保存できません: {$path}");
        $ready = false;
      } else {
        @chmod($path, 0600);
        pushLog("VAPID鍵ペアを新規生成しました: {$path}");
      }
    }

    if ($ready === false) {
      $keys = null;
    } else {
      // 生成した直後もここから読み直します。書けた物をそのまま使うのではなく
      // 実際に読めることまで確かめるためです。
      $loadedArr = @include $path;

      if (!is_array($loadedArr) || !isset($loadedArr['private_pem'], $loadedArr['public_raw_b64url'])) {
        error_log("[PusyuuPush] VAPID鍵ファイルの内容が不正です: {$path}");
        $keys = null;
      } else {
        $keys = $loadedArr;
      }
    }
  }

  return $keys;
}

// ---------------------------------------------------------------------
// VAPID JWT (ES256) の生成
// ---------------------------------------------------------------------

/**
 * ASN.1 DER形式のECDSA署名(可変長のr,s)を、JWSが要求する固定長rawのr||s(64byte)へ変換する。
 * openssl_sign() はDERしか返さないため、この変換を手で行う必要がある。
 */
function derSignatureToRaw(string $der, int $partLen = 32): ?string {
  if (strlen($der) < 8 || ($der[0] ?? '') !== "\x30") {
    // SEQUENCE tag で始まっていない = DER署名ではありません。
    $raw = null;
  } else {
    $offset = 1;
    $len = ord($der[$offset]);
    $offset++;
    if ($len & 0x80) { $offset += ($len & 0x7f); } // 長形式の長さは読み飛ばすだけでよい

    $readInt = static function (string $der, int &$offset) use ($partLen): ?string {
      if (($der[$offset] ?? '') !== "\x02") {
        // INTEGER tag でなければ読めません。
        $part = null;
      } else {
        $offset++;
        $intLen = ord($der[$offset] ?? "\x00");
        $offset++;
        $bytes = substr($der, $offset, $intLen);
        $offset += $intLen;
        // DERは符号の都合で先頭に0x00が付くことがあるので落としてから詰め直します。
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') { $bytes = "\x00"; }
        $part = (strlen($bytes) > $partLen) ? null : str_pad($bytes, $partLen, "\x00", STR_PAD_LEFT);
      }

      return $part;
    };

    $r = $readInt($der, $offset);
    $s = $readInt($der, $offset);
    $raw = ($r === null || $s === null) ? null : $r . $s;
  }

  return $raw;
}

/** $audience(プッシュ送信先のオリジン)向けのVAPID JWTを署名する。 */
function vapidSignJwt(string $audience): ?array {
  $keys = vapidKeys();
  $privateKey = ($keys === null) ? false : openssl_pkey_get_private($keys['private_pem']);

  if ($keys === null) {
    // vapidKeys() が既に理由を error_log へ残しているので、ここでは重ねません。
    $signed = null;

  } else if ($privateKey === false) {
    error_log('[PusyuuPush] VAPID秘密鍵の読み込みに失敗しました。');
    $signed = null;

  } else {
    $header = base64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => 'ES256'], JSON_UNESCAPED_SLASHES));
    $claims = base64UrlEncode(json_encode([
      'aud' => $audience,
      'exp' => time() + 12 * 3600,
      'sub' => VAPID_SUBJECT,
    ], JSON_UNESCAPED_SLASHES));
    $signingInput = $header . '.' . $claims;
    $derSignature = '';

    if (!openssl_sign($signingInput, $derSignature, $privateKey, OPENSSL_ALGO_SHA256)) {
      error_log('[PusyuuPush] VAPID JWTの署名に失敗しました。');
      $signed = null;
    } else {
      $rawSignature = derSignatureToRaw($derSignature);

      if ($rawSignature === null) {
        error_log('[PusyuuPush] VAPID署名のDER→raw変換に失敗しました。');
        $signed = null;
      } else {
        $signed = [
          'jwt'    => $signingInput . '.' . base64UrlEncode($rawSignature),
          'public' => $keys['public_raw_b64url'],
        ];
      }
    }
  }

  return $signed;
}

// ---------------------------------------------------------------------
// JSONLの共通読み書き(p-chat/p-reversiのtransact関数と同じ「flock+一時ファイル+rename」)
// ---------------------------------------------------------------------

/** subscriptions.jsonl・inbox.jsonl共通の暗号鍵(通知API専用の非公開フォルダに自己生成)。 */
function pusyuuPushStorageKey(): ?string {
  $hidden = pusyuuHiddenFilesDir();

  if ($hidden === null) {
    $key = null;
  } else {
    $key = pusyuuPushLoadOrCreateKey($hidden . '/' . STORAGE_KEY_FILE_NAME);
  }

  return $key;
}

function readJsonlPlain(string $file): array {
  $raw = file_exists($file) ? file_get_contents($file) : false;
  $rows = [];

  // 無い・読めない・空、のどれでも「まだ1件も無い」と同じ扱いにします。
  if ($raw !== false && trim($raw) !== '') {
    foreach (preg_split('/\r?\n/', $raw) as $line) {
      $line = trim($line);
      if ($line !== '') {
        $row = json_decode($line, true);
        if (is_array($row)) { $rows[] = $row; }
      }
    }
  }

  return $rows;
}

function writeJsonlPlain(string $file, array $rows): bool {
  $lines = [];
  foreach ($rows as $row) { $lines[] = json_encode($row, JSON_UNESCAPED_UNICODE); }

  $dir = dirname($file);
  // mkdir が失敗しても、他のリクエストが同時に作っていれば is_dir は真になります。
  $noDir = (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir));
  $tmp = $dir . '/.' . uniqid('pp_', true) . '.tmp';
  $fp = $noDir ? false : fopen($tmp, 'w');

  if ($fp === false) {
    $ok = false;
  } else {
    flock($fp, LOCK_EX);
    fwrite($fp, implode("\n", $lines));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    // いったん別名で書いてから rename します。途中で落ちても、読み手が
    // 半分だけ書かれたファイルを掴むことがありません(rename は不可分)。
    if (!rename($tmp, $file)) {
      @unlink($tmp);
      $ok = false;
    } else {
      $ok = true;
    }
  }

  return $ok;
}

/**
 * AES-256-GCMで暗号化して読み書きする。復号に失敗した場合(暗号化前の旧データ、
 * または鍵未取得)は旧形式の平文JSONLにフォールバックする。書き込みは鍵が
 * 取得できる限り常に暗号化して保存するため、一度でも書き込みが発生した時点で
 * 自然に暗号化データへ移行する。
 */
function readJsonl(string $file): array {
  $key = pusyuuPushStorageKey();
  $raw = ($key === null) ? '' : (file_exists($file) ? trim((string)file_get_contents($file)) : '');
  $plain = ($key === null || $raw === '') ? null : pusyuuPushAesGcmDecrypt($raw, $key);

  if ($key !== null && $raw === '') {
    // 鍵はあるがファイルが空。まだ1件も無い、で確定です。
    $rows = [];
  } else if ($plain !== null) {
    $rows = [];
    foreach (preg_split('/\r?\n/', $plain) as $line) {
      $line = trim($line);
      if ($line !== '') {
        $row = json_decode($line, true);
        if (is_array($row)) { $rows[] = $row; }
      }
    }
  } else {
    // 鍵が無い、または復号できなかった場合。暗号化前の旧データの可能性があるので、
    // 平文として読み直します。ここで諦めると、移行前のデータが見えなくなります。
    $rows = readJsonlPlain($file);
  }

  return $rows;
}

function writeJsonl(string $file, array $rows): bool {
  $key = pusyuuPushStorageKey();

  if ($key === null) {
    $ok = writeJsonlPlain($file, $rows);
  } else {
    // 鍵が取れる限り常に暗号化して保存します。一度でも書き込みが起きた時点で
    // そのファイルは自然に暗号化データへ移行します。
    $ok = pusyuuPushWriteEncryptedJsonlBlob($file, $rows, $key);
  }

  return $ok;
}

/** $mutator は array&$rows を受け取り ['save'=>bool, 'result'=>mixed] を返す。 */
function transactJsonl(string $file, callable $mutator): ?array {
  $lockFile = $file . '.lock';
  $dir = dirname($lockFile);
  // mkdir が失敗しても、他のリクエストが同時に作っていれば is_dir は真になります。
  $noDir = (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir));
  $lockHandle = $noDir ? false : fopen($lockFile, 'c');

  if ($lockHandle === false) {
    // 鍵をかけられないまま読み書きすると、同時に来た2つの更新が互いを消します。
    // 掛けられないなら何もしないのが正解です。
    $outcomeArr = null;
  } else {
    flock($lockHandle, LOCK_EX);
    $rows = readJsonl($file);
    $outcome = $mutator($rows);
    $status = false;

    // status は3値です。false=保存不要、true=保存できた、null=保存に失敗した。
    if (!empty($outcome['save'])) {
      $status = writeJsonl($file, $rows) ? true : null;
    }

    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
    $outcomeArr = ['status' => $status, 'result' => $outcome['result'] ?? null];
  }

  return $outcomeArr;
}

// ---------------------------------------------------------------------
// 購読(subscription)の保存
// ---------------------------------------------------------------------

function upsertSubscription(string $service, string $userid, array $subscription, string $ua): bool {
  $endpoint = (string)($subscription['endpoint'] ?? '');
  $p256dh   = (string)($subscription['keys']['p256dh'] ?? '');
  $auth     = (string)($subscription['keys']['auth'] ?? '');

  // 3つ揃っていないと、あとで送る段になって必ず失敗します。ここで畳みます。
  if ($endpoint === '' || $p256dh === '' || $auth === '') {
    $ok = false;
  } else {
    $tx = transactJsonl(SUBSCRIPTIONS_FILE, static function (array &$rows) use ($service, $userid, $endpoint, $p256dh, $auth, $ua): array {
      $now = time();
      $updated = false;

      // 同じ(サービス・利用者・宛先)の組があれば更新、無ければ足します。
      foreach ($rows as $i => $row) {
        if (($row['service'] ?? '') === $service && ($row['userid'] ?? '') === $userid && ($row['endpoint'] ?? '') === $endpoint) {
          $rows[$i]['p256dh']  = $p256dh;
          $rows[$i]['auth']    = $auth;
          $rows[$i]['ua']      = $ua;
          $rows[$i]['updated'] = $now;
          $updated = true;
          break;
        }
      }

      if ($updated === false) {
        $rows[] = [
          'service' => $service, 'userid' => $userid, 'endpoint' => $endpoint,
          'p256dh'  => $p256dh, 'auth' => $auth, 'ua' => $ua,
          'created' => $now, 'updated' => $now,
        ];
      }

      return ['save' => true, 'result' => true];
    });

    $ok = ($tx !== null && $tx['status'] === true);
  }

  return $ok;
}

function removeSubscription(string $service, string $userid, string $endpoint): void {
  transactJsonl(SUBSCRIPTIONS_FILE, static function (array &$rows) use ($service, $userid, $endpoint): array {
    $before = count($rows);
    $rows = array_values(array_filter($rows, static fn($r) =>
      !(($r['service'] ?? '') === $service && ($r['userid'] ?? '') === $userid && ($r['endpoint'] ?? '') === $endpoint)
    ));
    return ['save' => count($rows) !== $before, 'result' => true];
  });
}

function subscriptionsFor(string $service, string $userid): array {
  $rows = readJsonl(SUBSCRIPTIONS_FILE);
  return array_values(array_filter($rows, static fn($r) =>
    ($r['service'] ?? '') === $service && ($r['userid'] ?? '') === $userid
  ));
}

// ---------------------------------------------------------------------
// 通知チャンネル(どの経路で外へ出してよいか、という利用者の意思)
//
// ここの判定は send / subscribe / feed_create の内側で自動的に効く。呼び出し側
// サービスがチャンネルという概念を知らなくても正しく動く、というのがこの層の
// 一番の目的で、知っているサービスだけが channels_get/channels_set で設定画面を
// 出せる、という関係になっている。
// ---------------------------------------------------------------------

/** 引数がチャンネル名として正しいか。 */
function isKnownChannel(string $channel): bool {
  return in_array($channel, CHANNEL_ALL, true);
}

/** 引数が状態として正しいか。 */
function isKnownChannelState(string $state): bool {
  return $state === CHANNEL_UNSET || $state === CHANNEL_ALLOW || $state === CHANNEL_DENY;
}

/** 保存されていなければ unset。戻り値は必ず3つの定数のいずれか。 */
function channelState(string $service, string $userid, string $channel): string {
  // 保存が見つからなければ unset。戻り値は必ず3つの定数のいずれかです。
  $found = CHANNEL_UNSET;

  foreach (readJsonl(CHANNELS_FILE) as $row) {
    if (($row['service'] ?? '') === $service
      && ($row['userid'] ?? '') === $userid
      && ($row['channel'] ?? '') === $channel) {
      $state = (string)($row['state'] ?? '');
      // 知らない値が保存されていたら unset として扱います(勝手に許可にしない)。
      $found = isKnownChannelState($state) ? $state : CHANNEL_UNSET;
      break;
    }
  }

  return $found;
}

/** (service, userid)の全チャンネルの状態。設定画面と channels_get 用。 */
function channelStatesFor(string $service, string $userid): array {
  $states = [];
  foreach (CHANNEL_ALL as $channel) {
    $states[$channel] = channelState($service, $userid, $channel);
  }
  return $states;
}

/**
 * その状態で通知を外へ出してよいか。
 *
 * 「deny以外なら送る」とは書かない。3つの値それぞれについて明示的に判断を
 * 書いておくと、将来値が増えたときに取りこぼしが起きない(最後のreturnに
 * 落ちるだけになり、安全側で止まる)。
 */
function channelAllowsDelivery(string $state): bool {
  if ($state === CHANNEL_UNSET) {
    $allow = true;  // まだ何も言っていない = 登録操作そのものが意思表示
  } else if ($state === CHANNEL_ALLOW) {
    $allow = true;  // 明示的に許可した
  } else if ($state === CHANNEL_DENY) {
    $allow = false; // 錠。本人が解除するまで動かない
  } else {
    $allow = false; // 未知の値は安全側(出さない)
  }

  return $allow;
}

/**
 * 状態を書き込む。$by には呼び出し元のサービス名を入れる(監査用)。
 * 直近 CHANNEL_AUDIT_MAX 件の変更履歴を行の中に残す。
 */
function channelSetState(string $service, string $userid, string $channel, string $state, string $by): bool {
  $tx = transactJsonl(CHANNELS_FILE, static function (array &$rows) use ($service, $userid, $channel, $state, $by): array {
    $now = time();
    $entry = ['state' => $state, 'by' => $by, 'at' => $now];
    $outcome = null;

    foreach ($rows as $i => $row) {
      if (($row['service'] ?? '') === $service
        && ($row['userid'] ?? '') === $userid
        && ($row['channel'] ?? '') === $channel) {

        if ((string)($row['state'] ?? '') === $state) {
          // 同じ値の書き込みは履歴を汚さないよう、保存せずに終わります。
          $outcome = ['save' => false, 'result' => true];
        } else {
          $audit = is_array($row['audit'] ?? null) ? $row['audit'] : [];
          $audit[] = $entry;
          if (count($audit) > CHANNEL_AUDIT_MAX) {
            $audit = array_slice($audit, count($audit) - CHANNEL_AUDIT_MAX);
          }
          $rows[$i]['state']   = $state;
          $rows[$i]['updated'] = $now;
          $rows[$i]['audit']   = $audit;
          $outcome = ['save' => true, 'result' => true];
        }
        break;
      }
    }

    // 既存の行が1つも当たらなかったときだけ、新しく足します。
    if ($outcome === null) {
      $rows[] = [
        'service' => $service, 'userid' => $userid, 'channel' => $channel,
        'state'   => $state, 'updated' => $now, 'audit' => [$entry],
      ];
      $outcome = ['save' => true, 'result' => true];
    }

    return $outcome;
  });

  // status が false(保存不要)も成功です。null(保存に失敗)だけが失敗。
  $ok = ($tx !== null && ($tx['status'] === true || $tx['status'] === false));

  return $ok;
}

/** 監査用の変更履歴。無ければ空配列。 */
function channelAuditFor(string $service, string $userid): array {
  $audit = [];

  foreach (readJsonl(CHANNELS_FILE) as $row) {
    if (($row['service'] ?? '') === $service && ($row['userid'] ?? '') === $userid) {
      foreach ((is_array($row['audit'] ?? null) ? $row['audit'] : []) as $entry) {
        $audit[] = array_merge(['channel' => (string)($row['channel'] ?? '')], $entry);
      }
    }
  }

  usort($audit, static fn($a, $b) => ((int)($b['at'] ?? 0)) <=> ((int)($a['at'] ?? 0)));
  $recent = array_slice($audit, 0, CHANNEL_AUDIT_MAX * count(CHANNEL_ALL));

  return $recent;
}

// ---------------------------------------------------------------------
// 未読通知(inbox)の保存
// ---------------------------------------------------------------------

/**
 * 溜まりすぎた行を落とす。3つの上限を順に当てる。
 *
 * 【この関数がファイルサイズの唯一の出口である】RSSだけで受け取っている利用者は
 * 既読を返す手段が無い(リーダーは ack を投げられない)。つまり ack 待ちでは
 * 行が永久に残る。ここの保持期間切れだけがそれを掃除する。消さないとinbox.jsonlが
 * 際限なく育ち、毎回の復号+パースが重くなる。
 */
function sweepInboxRows(array &$rows, string $service, string $userid): void {
  $cutoff = time() - INBOX_HISTORY_DAYS * 86400;

  $mine = [];
  $others = [];
  foreach ($rows as $row) {
    if (($row['service'] ?? '') === $service && ($row['userid'] ?? '') === $userid) {
      $mine[] = $row;
    } else {
      $others[] = $row;
    }
  }

  // 1) 保持期間を過ぎたものを落とす。
  $kept = [];
  foreach ($mine as $row) {
    if ((int)($row['created'] ?? 0) >= $cutoff) { $kept[] = $row; }
  }

  // 2) 未読が多すぎる場合は古い未読から落とす(これは従来からの挙動そのまま)。
  $unreadIds = [];
  foreach ($kept as $row) {
    if (empty($row['acked'])) { $unreadIds[] = (string)($row['id'] ?? ''); }
  }
  if (count($unreadIds) > INBOX_MAX_PER_USER) {
    $dropIds = array_slice($unreadIds, 0, count($unreadIds) - INBOX_MAX_PER_USER);
    $kept = array_values(array_filter($kept, static fn($r) => !in_array((string)($r['id'] ?? ''), $dropIds, true)));
  }

  // 3) 既読も含めた総数の上限(= RSSフィードが遡れる履歴の長さ)。
  if (count($kept) > INBOX_HISTORY_MAX_PER_USER) {
    $kept = array_slice($kept, count($kept) - INBOX_HISTORY_MAX_PER_USER);
  }

  // 他の(service,userid)の行との前後は入れ替わるが、絞り込みは必ず
  // (service,userid)単位で行われ、読み出し側も created で並べ直すため
  // 順序の意味は失われない。
  $rows = array_merge($others, $kept);
}

function appendInbox(string $service, string $userid, string $title, string $body, string $url, ?string $tag, ?string $icon): void {
  transactJsonl(INBOX_FILE, static function (array &$rows) use ($service, $userid, $title, $body, $url, $tag, $icon): array {
    $rows[] = [
      'id' => bin2hex(random_bytes(8)), 'service' => $service, 'userid' => $userid,
      'title' => $title, 'body' => $body, 'url' => $url, 'tag' => $tag, 'icon' => $icon,
      'created' => time(), 'acked' => null,
    ];
    sweepInboxRows($rows, $service, $userid);
    return ['save' => true, 'result' => true];
  });
}

/**
 * 同じ内容を複数の利用者のinboxへ一度に積む(ブロードキャスト用)。
 *
 * 【なぜ appendInbox を人数ぶん呼ばないか】appendInbox は1回ごとに
 * inbox.jsonl を丸ごと読んで復号して書き戻す。人数ぶん繰り返すとファイルの
 * 全書き換えが人数回起き、購読者が増えるほど不利になる。ここは1回のロックの
 * 中で全員ぶんを追記して1回だけ書く。
 */
function appendInboxBroadcast(string $service, array $userids, string $title, string $body, string $url, ?string $tag, ?string $icon): int {
  if (empty($userids)) {
    // 宛先が1人も居ない。ロックを取る意味も無いので、書かずに0を返します。
    $count = 0;
  } else {
    $tx = transactJsonl(INBOX_FILE, static function (array &$rows) use ($service, $userids, $title, $body, $url, $tag, $icon): array {
      $now = time();

      foreach ($userids as $userid) {
        $rows[] = [
          'id' => bin2hex(random_bytes(8)), 'service' => $service, 'userid' => $userid,
          'title' => $title, 'body' => $body, 'url' => $url, 'tag' => $tag, 'icon' => $icon,
          'created' => $now, 'acked' => null,
        ];
      }
      foreach ($userids as $userid) {
        sweepInboxRows($rows, $service, $userid);
      }

      return ['save' => true, 'result' => count($userids)];
    });

    $count = ($tx === null) ? 0 : (int)($tx['result'] ?? 0);
  }

  return $count;
}

/**
 * そのサービスで「通知を受け取りたい」と意思表示している利用者の一覧。
 *
 * 購読(端末を登録した)かフィード(RSSを発行した)のどちらかを持っている人、と
 * 定義する。どちらも押さなければ存在しないので、これがそのまま「配ってよい相手」に
 * なる(ブロードキャストを勝手に全利用者へ配らないための線引き)。
 */
function broadcastRecipients(string $service): array {
  $userids = [];
  foreach (readJsonl(SUBSCRIPTIONS_FILE) as $row) {
    if (($row['service'] ?? '') !== $service) { continue; }
    $userid = (string)($row['userid'] ?? '');
    if ($userid !== '') { $userids[$userid] = true; }
  }
  foreach (readJsonl(FEEDS_FILE) as $row) {
    if (($row['service'] ?? '') !== $service || !empty($row['revoked'])) { continue; }
    $userid = (string)($row['userid'] ?? '');
    if ($userid !== '') { $userids[$userid] = true; }
  }
  return array_keys($userids);
}

/**
 * 未読だけを返す。
 *
 * 既存データには 'acked' キーが無いが、その場合 empty() が真になり未読として
 * 扱われる。つまり ack の意味を「削除」から「フラグ」へ変えても、この関数の
 * 戻り値は従来と同じになる。移行処理は不要。
 */
function inboxFor(string $service, string $userid): array {
  $rows = readJsonl(INBOX_FILE);
  return array_values(array_filter($rows, static fn($r) =>
    ($r['service'] ?? '') === $service && ($r['userid'] ?? '') === $userid && empty($r['acked'])
  ));
}

/** 既読も含めた履歴を新しい順に返す。RSSフィードが読むのはこちら。 */
function inboxHistoryFor(string $service, string $userid, int $limit): array {
  $rows = array_values(array_filter(readJsonl(INBOX_FILE), static fn($r) =>
    ($r['service'] ?? '') === $service && ($r['userid'] ?? '') === $userid
  ));
  usort($rows, static fn($a, $b) => ((int)($b['created'] ?? 0)) <=> ((int)($a['created'] ?? 0)));
  return array_slice($rows, 0, $limit);
}

/**
 * 既読にする(削除ではなく 'acked' に時刻を書く)。$ids が空なら全件。
 * なぜ削除をやめたかは INBOX_HISTORY_DAYS のコメントを参照。
 */
function ackInbox(string $service, string $userid, array $ids): void {
  transactJsonl(INBOX_FILE, static function (array &$rows) use ($service, $userid, $ids): array {
    $now = time();
    $changed = 0;
    foreach ($rows as $i => $row) {
      if (($row['service'] ?? '') !== $service || ($row['userid'] ?? '') !== $userid) { continue; }
      if (!empty($row['acked'])) { continue; }
      if (!empty($ids) && !in_array((string)($row['id'] ?? ''), $ids, true)) { continue; }
      $rows[$i]['acked'] = $now;
      $changed++;
    }
    return ['save' => $changed > 0, 'result' => $changed];
  });
}

// ---------------------------------------------------------------------
// RSSフィード
//
// 【設計の肝:URLを2つに割る】
//   購読URL: ?feed=<token>            … RSSリーダーに貼る。暗号文しか得られない
//   閲覧URL: ?view=1#t=<token>&k=<鍵> … 自分がブックマークする。鍵はここだけ
//
// 鍵は必ずフラグメント(#以降)に置く。フラグメントはブラウザからサーバへ
// 送信されないため、アクセスログにも中継にも残らない。
//
// 【破ってはいけない不変条件】フィードのXML/JSONの中に鍵を絶対に入れないこと。
// アイテムのリンクに付けるのは ?view=1#t=<token> までで、&k= を足してはいけない。
// これを破るとRSSリーダーが鍵を手に入れ、sealedモードの意味が完全に消える。
// (tokenの方はリーダーが元から持っている値なので、フィードに現れても新しい
//  漏洩にはならない)
//
// 【鍵をサーバが持つことについて】sealedの鍵はサーバ側で生成し feeds.jsonl に
// 保存する。E2Eにはならないが、ここでE2Eを目指すのは無意味である: 通知の平文を
// 作っているのはサーバ自身(inbox.jsonl)なので、鍵をクライアント生成にしても
// サーバは元から平文を持っている。守る相手はRSSリーダー事業者とURLを拾った
// 第三者であって、サーバではない。
// ---------------------------------------------------------------------

/** トークンからフィード行を引く。失効済みは見つからない扱い。 */
function feedFindByToken(string $token): ?array {
  $key = ($token === '') ? null : sharedKeyRaw();
  $found = null;

  if ($key !== null) {
    // 保存してあるのは生トークンではなくHMACなので、こちらも同じ作り方で
    // 突き合わせます。比較は hash_equals(タイミング攻撃を避けるため)。
    $hash = hash_hmac('sha256', $token, $key);

    foreach (readJsonl(FEEDS_FILE) as $row) {
      if (hash_equals((string)($row['token_hash'] ?? ''), $hash)) {
        // 失効済みは「見つからなかった」と同じ扱いにします。
        $found = empty($row['revoked']) ? $row : null;
        break;
      }
    }
  }

  return $found;
}

/** (service, userid)の有効なフィード一覧。トークンは復元できない(保存していない)。 */
function feedsFor(string $service, string $userid): array {
  return array_values(array_filter(readJsonl(FEEDS_FILE), static fn($r) =>
    ($r['service'] ?? '') === $service && ($r['userid'] ?? '') === $userid && empty($r['revoked'])
  ));
}

/**
 * フィードを発行する。戻り値の 'token' と 'key_b64' はこの一度きりしか返らない。
 *
 * 【なぜ生トークンを保存しないか】保存するのは共有鍵によるHMACだけ。こうして
 * おくと、万一ストレージが読まれても、そこから動くURLを再構成できない。
 * 既存の expectedApiSecret() とまったく同じ考え方。代償として、発行時に
 * 表示し損ねたトークンは二度と取り出せない(アカウントの復旧コードと同じ性質)。
 */
function feedCreate(string $service, string $userid, string $mode): array {
  $key = sharedKeyRaw();

  if ($key === null) {
    $result = ['ok' => false, 'error' => 'server_misconfigured'];
  } else {
    $token   = base64UrlEncode(random_bytes(32));
    $keyB64  = $mode === FEED_MODE_SEALED ? base64_encode(random_bytes(32)) : '';
    $now     = time();
    // 【生トークンは保存しません】保存するのはHMACだけ。こうしておくと、
    // 万一このファイルが読まれても、そこから動くURLを再構成できません。
    $newRow  = [
      'feed_id'    => bin2hex(random_bytes(8)),
      'service'    => $service,
      'userid'     => $userid,
      'mode'       => $mode,
      'token_hash' => hash_hmac('sha256', $token, $key),
      'key_b64'    => $keyB64,
      'created'    => $now,
      'last_poll'  => 0,
      'poll_count' => 0,
      'revoked'    => 0,
    ];

    $tx = transactJsonl(FEEDS_FILE, static function (array &$rows) use ($newRow, $service, $userid, $now): array {
      // 失効済みと、長く放置されたフィードの行をここで掃除する。
      // last_poll が 0 のまま(= 一度も取得されていない)ものは created を基準にする。
      $idleCutoff = $now - FEED_IDLE_EXPIRE_DAYS * 86400;
      $rows = array_values(array_filter($rows, static function ($r) use ($idleCutoff): bool {
        if (!empty($r['revoked'])) {
          $keep = false;
        } else {
          $lastSeen = (int)($r['last_poll'] ?? 0);
          if ($lastSeen === 0) { $lastSeen = (int)($r['created'] ?? 0); }
          $keep = ($lastSeen >= $idleCutoff);
        }

        return $keep;
      }));

      $mine = 0;
      foreach ($rows as $r) {
        if (($r['service'] ?? '') === $service && ($r['userid'] ?? '') === $userid) { $mine++; }
      }

      // 上限に達していても save は true のままにします。上でやった掃除の結果を
      // 捨てないためです(掃除だけは残す)。
      if ($mine >= FEED_MAX_PER_USER) {
        $outcome = ['save' => true, 'result' => 'too_many'];
      } else {
        $rows[] = $newRow;
        $outcome = ['save' => true, 'result' => 'created'];
      }

      return $outcome;
    });

    if ($tx === null || $tx['status'] !== true) {
      $result = ['ok' => false, 'error' => 'storage_failed'];
    } else if ($tx['result'] === 'too_many') {
      $result = ['ok' => false, 'error' => 'too_many_feeds'];
    } else {
      // token と key_b64 を返せるのはこの一度きりです(保存していないため)。
      $result = ['ok' => true, 'feed' => $newRow, 'token' => $token, 'key_b64' => $keyB64];
    }
  }

  return $result;
}

function feedRevoke(string $service, string $userid, string $feedId): bool {
  $tx = transactJsonl(FEEDS_FILE, static function (array &$rows) use ($service, $userid, $feedId): array {
    $before = count($rows);
    $rows = array_values(array_filter($rows, static fn($r) =>
      !(($r['service'] ?? '') === $service && ($r['userid'] ?? '') === $userid && ($r['feed_id'] ?? '') === $feedId)
    ));
    return ['save' => count($rows) !== $before, 'result' => count($rows) !== $before];
  });
  return $tx !== null && $tx['result'] === true;
}

/** (service, userid)のフィードを全部消す。チャンネルをdeny+purgeしたときに使う。 */
function feedRevokeAllFor(string $service, string $userid): int {
  $tx = transactJsonl(FEEDS_FILE, static function (array &$rows) use ($service, $userid): array {
    $before = count($rows);
    $rows = array_values(array_filter($rows, static fn($r) =>
      !(($r['service'] ?? '') === $service && ($r['userid'] ?? '') === $userid)
    ));
    return ['save' => count($rows) !== $before, 'result' => $before - count($rows)];
  });
  return $tx === null ? 0 : (int)($tx['result'] ?? 0);
}

/**
 * 取得された時刻を記録する。
 *
 * 【呼ぶ場所に注意】レート制限で304を返したときは呼んではいけない。そこで
 * last_poll を更新してしまうと、短い間隔で叩き続けるリーダーに対して制限窓が
 * ずっとスライドし続け、いつまで経っても中身が返らなくなる。
 */
function feedTouch(string $feedId, int $when): void {
  transactJsonl(FEEDS_FILE, static function (array &$rows) use ($feedId, $when): array {
    foreach ($rows as $i => $row) {
      if (($row['feed_id'] ?? '') !== $feedId) { continue; }
      $rows[$i]['last_poll']  = $when;
      $rows[$i]['poll_count'] = (int)($row['poll_count'] ?? 0) + 1;
      return ['save' => true, 'result' => true];
    }
    return ['save' => false, 'result' => false];
  });
}

// ---------------------------------------------------------------------
// フィードの整形(モードごとに何を載せるか)
// ---------------------------------------------------------------------

/**
 * XMLのテキストノードに置ける形へ直す。
 *
 * 制御文字の除去を先に行うのが肝。XML 1.0 はタブ・改行・復帰を除く制御文字を
 * 一切許さないので、通知本文にそれが1個混ざるだけでリーダー側がフィード全体を
 * パースエラーにする(1件だけ壊れるのではなく、全部読めなくなる)。
 */
function xmlText(string $s): string {
  $cleaned = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u', '', $s);

  if ($cleaned === null) {
    // 不正なUTF-8が混ざっているとpreg_replaceがnullを返す。バイト単位で落とす。
    $cleaned = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $s);
    if ($cleaned === null) { $cleaned = ''; }
  }

  $escaped = htmlspecialchars($cleaned, ENT_QUOTES | ENT_XML1 | ENT_SUBSTITUTE, 'UTF-8');

  return $escaped;
}

/** sealedモードで1件を暗号化する。形式は保存用と同じ base64(IV 12 + TAG 16 + 暗号文)。 */
function feedSealItem(array $feed, array $item): ?string {
  $rawKey = base64_decode((string)($feed['key_b64'] ?? ''), true);
  $plain = ($rawKey === false || strlen($rawKey) !== 32)
    ? false
    : json_encode([
        'title'   => (string)($item['title'] ?? ''),
        'body'    => (string)($item['body'] ?? ''),
        'url'     => (string)($item['url'] ?? ''),
        'created' => (int)($item['created'] ?? 0),
      ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

  // 鍵が使えない・組み立てられない、のどちらでも null。
  // 【ここで平文へ落とさないこと】落とすと、封をしたつもりの通知が素で出ます。
  if ($plain === false) {
    $cipher = null;
  } else {
    $cipher = pusyuuPushAesGcmEncrypt($plain, $rawKey);
  }

  return $cipher;
}

/**
 * 1件をモードに応じた「載せる形」にする。
 *
 * モードごとに独立して書く。「sealedでなければ本文を載せる」のような書き方だと、
 * 将来モードを1つ足したときに、新モードが既定で本文を載せてしまう。
 */
function feedShapeItem(array $feed, array $item, string $viewUrl): array {
  $mode    = (string)($feed['mode'] ?? FEED_MODE_DEFAULT);
  $service = (string)($feed['service'] ?? '');
  $title   = (string)($item['title'] ?? '');
  $body    = (string)($item['body'] ?? '');
  $url     = (string)($item['url'] ?? '');
  $link    = $url !== '' ? $url : $viewUrl;
  $cipher  = ($mode === FEED_MODE_SEALED) ? feedSealItem($feed, $item) : null;

  // 【モードごとに独立して書くこと】「sealedでなければ本文を載せる」のような
  // 書き方にすると、将来モードを1つ足したときに、新モードが既定で本文を載せます。
  if ($mode === FEED_MODE_OPEN) {
    $shaped = ['title' => $title, 'body' => $body, 'link' => $link, 'cipher' => ''];

  } else if ($mode === FEED_MODE_NOTICE) {
    $shaped = [
      'title'  => $service . ' に新しい通知があります',
      'body'   => '内容はこのフィードには含まれていません。リンク先で確認してください。',
      'link'   => $link,
      'cipher' => '',
    ];

  } else if ($mode === FEED_MODE_SEALED && $cipher === null) {
    // 鍵が壊れている等で暗号化できないときに平文へ落ちてはいけない。
    $shaped = ['title' => '🔒 ' . $service . ' の通知(復号できません)', 'body' => '', 'link' => $viewUrl, 'cipher' => ''];

  } else if ($mode === FEED_MODE_SEALED) {
    $shaped = [
      'title'  => '🔒 ' . $service . ' の暗号化された通知',
      'body'   => '鍵を持つ閲覧ページでのみ読めます。',
      'link'   => $viewUrl,
      'cipher' => $cipher,
    ];

  } else {
    // 未知のモードは最も情報を出さない扱いにする。
    $shaped = ['title' => $service . ' に新しい通知があります', 'body' => '', 'link' => $viewUrl, 'cipher' => ''];
  }

  return $shaped;
}

/** 中身が変わったかどうかだけを表す弱いETag。件数とIDとモードから作る。 */
function feedEtag(array $feed, array $items): string {
  $ids = [];
  foreach ($items as $item) { $ids[] = (string)($item['id'] ?? ''); }
  $seed = (string)($feed['mode'] ?? '') . '|' . implode(',', $ids);
  return 'W/"' . substr(sha1($seed), 0, 20) . '"';
}

function feedRenderRss(array $feed, array $items, string $token): string {
  $base    = publicBaseUrl();
  $feedUrl = $base . '?feed=' . rawurlencode($token);
  $viewUrl = $base . '?view=1#t=' . rawurlencode($token); // ← 鍵(&k=)は絶対に付けない
  $service = (string)($feed['service'] ?? '');
  $mode    = (string)($feed['mode'] ?? FEED_MODE_DEFAULT);

  $out  = '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
  $out .= '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">' . "\n";
  $out .= '  <channel>' . "\n";
  $out .= '    <title>' . xmlText($service . ' の通知') . '</title>' . "\n";
  $out .= '    <link>' . xmlText($viewUrl) . '</link>' . "\n";
  $out .= '    <description>' . xmlText('プッシュ通知を受け取れない環境向けの、' . $service . ' の通知フィード(モード: ' . $mode . ')') . '</description>' . "\n";
  $out .= '    <language>ja</language>' . "\n";
  $out .= '    <ttl>' . (int)ceil(FEED_MIN_POLL_SEC / 60) . '</ttl>' . "\n";
  $out .= '    <atom:link rel="self" type="application/rss+xml" href="' . xmlText($feedUrl) . '" />' . "\n";

  foreach ($items as $item) {
    $shaped = feedShapeItem($feed, $item, $viewUrl);
    $description = $shaped['body'];
    if ($shaped['cipher'] !== '') {
      $description .= "\n\n-----BEGIN PUSYUU SEALED-----\n" . $shaped['cipher'] . "\n-----END PUSYUU SEALED-----";
    }
    $out .= '    <item>' . "\n";
    $out .= '      <title>' . xmlText($shaped['title']) . '</title>' . "\n";
    $out .= '      <link>' . xmlText($shaped['link']) . '</link>' . "\n";
    $out .= '      <guid isPermaLink="false">' . xmlText('pusyuu-push-' . (string)($item['id'] ?? '')) . '</guid>' . "\n";
    $out .= '      <pubDate>' . xmlText(gmdate('D, d M Y H:i:s', (int)($item['created'] ?? time())) . ' GMT') . '</pubDate>' . "\n";
    $out .= '      <description>' . xmlText($description) . '</description>' . "\n";
    $out .= '    </item>' . "\n";
  }

  $out .= '  </channel>' . "\n";
  $out .= '</rss>' . "\n";
  return $out;
}

/** 閲覧ページ(?view=1)が読む形。XMLをJSでパースせずに済ませるためのもの。 */
function feedRenderJson(array $feed, array $items, string $token): string {
  $viewUrl = publicBaseUrl() . '?view=1#t=' . rawurlencode($token);
  $out = [];
  foreach ($items as $item) {
    $shaped = feedShapeItem($feed, $item, $viewUrl);
    $out[] = [
      'id'      => (string)($item['id'] ?? ''),
      'title'   => $shaped['title'],
      'body'    => $shaped['body'],
      'link'    => $shaped['link'],
      'cipher'  => $shaped['cipher'],
      'created' => (int)($item['created'] ?? 0),
    ];
  }
  return (string)json_encode([
    'ok'      => true,
    'service' => (string)($feed['service'] ?? ''),
    'mode'    => (string)($feed['mode'] ?? FEED_MODE_DEFAULT),
    'items'   => $out,
  ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

// ---------------------------------------------------------------------
// 通知設定画面へ入るための一時チケット
//
// 【なぜ保存しないか】チケットは署名だけで成立する(payload + HMAC)。ファイルに
// 持たせると、発行のたびに書き込みとロックが発生し、期限切れの掃除も要る。
// 署名方式ならどちらも不要で、鍵を替えれば全部まとめて無効にできる。
//
// 【CSRFについて】この画面のPOSTはチケットそのものを資格情報にしている。
// 攻撃者はチケットを知らないので、別サイトからのPOSTは成立しない。かわりに
// チケットがReferer経由で漏れないよう、画面には no-referrer を必ず付ける。
// ---------------------------------------------------------------------

/**
 * 戻り先URLとして受け入れてよいか。
 *
 * サービスは合言葉を持っている相手なので基本的に信用するが、javascript: のような
 * スキームをそのまま <a href> やリダイレクトに載せると、この画面が踏み台になる。
 * スキームだけは必ず確認する。
 */
function settingsValidReturnUrl(string $url): string {
  $parts = ($url === '') ? false : parse_url($url);
  $scheme = (is_array($parts) && isset($parts['scheme'])) ? strtolower((string)$parts['scheme']) : '';

  // 【スキームの確認を外さないこと】javascript: のようなURLをそのまま
  // <a href> やリダイレクトに載せると、この画面が踏み台になります。
  if ($url === '') {
    $safe = '';
  } else if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
    $safe = '';
  } else if ($scheme !== 'https' && $scheme !== 'http') {
    $safe = '';
  } else {
    $safe = $url;
  }

  return $safe;
}

/**
 * 署名付きトークンを作る。$kind で用途を分けるのは、URLに載せるチケットと
 * Cookieに入れるセッションを取り違えて使えないようにするため(片方が漏れても
 * もう片方として通用しない)。
 */
function settingsSignToken(string $kind, string $service, string $userid, string $returnUrl, int $ttl): ?string {
  $key = sharedKeyRaw();
  $json = ($key === null) ? false : json_encode([
    'k'       => $kind,
    'service' => $service,
    'userid'  => $userid,
    'return'  => settingsValidReturnUrl($returnUrl),
    'exp'     => time() + $ttl,
  ], JSON_UNESCAPED_UNICODE);

  if ($json === false) {
    $token = null;
  } else {
    $payload = base64UrlEncode($json);
    $sig     = base64UrlEncode(hash_hmac('sha256', $payload, $key, true));
    $token   = $payload . '.' . $sig;
  }

  return $token;
}

function settingsVerifyToken(string $token, string $kind): ?array {
  $key = sharedKeyRaw();
  $parts = explode('.', $token);
  // 署名が合っているときだけ中身を読みます。先に読んで後から検証すると、
  // 検証の追加を忘れた枝から改ざんされた値が入ります。
  $signed = ($key !== null)
    && (count($parts) === 2)
    && hash_equals(base64UrlEncode(hash_hmac('sha256', $parts[0], $key, true)), $parts[1]);

  $json = $signed ? base64_decode(strtr($parts[0], '-_', '+/'), true) : false;
  $decoded = ($json === false) ? null : json_decode($json, true);

  if (!is_array($decoded)) {
    $claims = null;
  } else if ((string)($decoded['k'] ?? '') !== $kind) {
    // 用途が違うトークン。URLに載せるチケットとCookieのセッションを
    // 取り違えて使えないようにするための線引きです。
    $claims = null;
  } else {
    $service = (string)($decoded['service'] ?? '');
    $userid  = (string)($decoded['userid'] ?? '');
    $exp     = (int)($decoded['exp'] ?? 0);

    if ($service === '' || $userid === '' || $exp < time()) {
      $claims = null;
    } else {
      $claims = [
        'service' => $service,
        'userid'  => $userid,
        'return'  => settingsValidReturnUrl((string)($decoded['return'] ?? '')),
        'exp'     => $exp,
      ];
    }
  }

  return $claims;
}

function settingsTicketIssue(string $service, string $userid, string $returnUrl = ''): ?string {
  $ticket = settingsSignToken('ticket', $service, $userid, $returnUrl, SETTINGS_TICKET_TTL);

  return $ticket;
}

/**
 * チケットを使用済みにする。既に使われていたら false。
 *
 * 保存するのはチケットそのものではなくSHA-256(ファイルが読まれても、そこから
 * 有効なURLを組み立てられないようにする)。期限を過ぎた行はここで掃除するので、
 * このファイルは使用中のチケットの数までしか育たない。
 */
function settingsTicketConsume(string $ticket, int $exp): bool {
  $fingerprint = hash('sha256', $ticket);
  $tx = transactJsonl(TICKETS_USED_FILE, static function (array &$rows) use ($fingerprint, $exp): array {
    $now = time();
    $before = count($rows);
    $kept = [];
    $seen = false;
    foreach ($rows as $row) {
      if ((int)($row['exp'] ?? 0) < $now) { continue; } // 期限切れは捨てる
      if (hash_equals((string)($row['fp'] ?? ''), $fingerprint)) { $seen = true; }
      $kept[] = $row;
    }
    if ($seen) {
      $rows = $kept;
      return ['save' => count($kept) !== $before, 'result' => false]; // 掃除だけ保存する
    }
    $kept[] = ['fp' => $fingerprint, 'exp' => $exp];
    $rows = $kept;
    return ['save' => true, 'result' => true];
  });
  // 書き込めなかった場合は「使えない」側に倒す。二重に使われるより、
  // もう一度サービスの画面から開き直してもらう方が安全。
  return $tx !== null && $tx['result'] === true && $tx['status'] === true;
}

function settingsCookieIssue(array $claims): ?string {
  return settingsSignToken('session', $claims['service'], $claims['userid'], (string)$claims['return'], SETTINGS_COOKIE_TTL);
}

/** Cookieの適用範囲。このAPIのディレクトリ配下だけに限る。 */
function settingsCookiePath(): string {
  $dir = str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/index.php')));
  return $dir === '' || $dir === '.' ? '/' : rtrim($dir, '/') . '/';
}

// 【かつてここにあった「送り出し(bounce)」について】
// 設定画面でプッシュ/デスクトップの「使う」を押したら、サービスのオリジンへ
// リダイレクトして許可を取らせる、という仕組みを一度作ったが撤去した。理由は2つ。
//
//   1. 着地した先で自動的に許可を求めることはできない。ブラウザは操作を伴わない
//      許可要求を自動的に拒否し(「対話がないため自動的にブロックしました」)、
//      しかも拒否の記録だけが残って以後は正規の手順でも求められなくなる。
//   2. 結局サービスの画面でボタンを押すことになるなら、切り替えそのものを
//      サービスの画面に置いた方が短い。押した場所で許可も購読も完結する。
//
// いまはプッシュ/デスクトップの切り替えはサービス自身の画面にあり、その裏で
// ?api=channels_set を呼ぶ。この画面はRSS専用。

// ---------------------------------------------------------------------
// プッシュの配送(空ペイロード。VAPIDで署名するだけ)
// ---------------------------------------------------------------------

/**
 * 任意のURLへ、空ボディ・任意ヘッダでPOSTし、HTTPステータスコードを返す。通信自体に失敗したらnull。
 */
function httpPostEmpty(string $url, array $headers): ?int {
  $headerLines = '';
  foreach ($headers as $k => $v) { $headerLines .= "{$k}: {$v}\r\n"; }

  // 送るのはストリーム(file_get_contents)だけです。以前は届かなければ curl でもう一度送っていましたが、
  // 素のPHPに curl は無く(CODING_STYLE 12)、ストリームで届かない相手には curl でも届かないので外しました。
  // allow_url_fopen が Off のサーバでは送れません(理由を残して null)。
  $status = null;
  $context = stream_context_create([
    'http' => [
      'method'        => 'POST',
      'header'        => $headerLines,
      'content'       => '',
      'timeout'       => PUSH_HTTP_TIMEOUT,
      'ignore_errors' => true,
    ],
  ]);
  $result = ini_get('allow_url_fopen') ? @file_get_contents($url, false, $context) : false;
  // PHP 8.5 で $http_response_header は非推奨。8.4 より前には http_get_last_response_headers() が無いので、使える方で読みます
  // (pusyuu_registry_client.php と同じ形。この行を別の関数へ切り出すと、8.4 より前は $http_response_header が見えなくなります)。
  $responseHeaders = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
  $statusLine = ($result === false) ? '' : (string)($responseHeaders[0] ?? '');

  if (!ini_get('allow_url_fopen')) {
    error_log('[PusyuuPush] allow_url_fopen が Off のため、プッシュを送れません。');
  } else if ($result === false) {
    // 通信そのものに失敗しました(名前が引けない・繋がらない・時間切れ)。
    $status = null;
  } else if (preg_match('/\s(\d{3})(\s|$)/', $statusLine, $m) === 1) {
    $status = (int)$m[1];
  } else {
    // 番号が読み取れないときは200として扱います(応答自体は返ってきているため)。
    $status = 200;
  }

  return $status;
}

function sendPushToSubscription(array $subscription): ?int {
  $endpoint = (string)($subscription['endpoint'] ?? '');
  $parts = ($endpoint === '') ? [] : (parse_url($endpoint) ?: []);
  $hasTarget = isset($parts['scheme'], $parts['host']);
  // 宛先が読めないときは署名もしません(誰宛ての署名か決められないため)。
  $signed = $hasTarget
    ? vapidSignJwt($parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : ''))
    : null;

  if ($signed === null) {
    $status = null;
  } else {
    $status = httpPostEmpty($endpoint, [
      'Authorization'  => 'vapid t=' . $signed['jwt'] . ', k=' . $signed['public'],
      'TTL'            => (string)PUSH_TTL,
      // 'high'にしないと、Android端末のDoze/バッテリー節約モード中はOS側の判断で配送が
      // 数分〜数十分単位まで遅延することがある(既定のnormalは省電力を優先して間引かれうる)。
      // 空ペイロードの「起こすだけ」のプッシュなので、高優先度にしても送信量的な問題はない。
      'Urgency'        => 'high',
      'Content-Length' => '0',
    ]);
  }

  return $status;
}

// =====================================================================
// 公開ルート(合言葉なし。トークン/チケット自身が資格情報)
//
// 【なぜ「全アクションに合言葉必須」の原則を破っていないのか】ここで守って
// いるのは「合言葉という特定の文字列」ではなく「認証されていない読み出しを
// させない」という性質のほう。フィードのトークンは256bitの乱数で、それ自体が
// 資格情報になっている(RSSリーダーはCookieもヘッダも足せないので、URLに
// 載せる以外の方法が存在しない)。合言葉を要求すると、合言葉を全リーダーへ
// 配ることになり、そちらの方がはるかに危ない。
//
// なお、これらの口が必要なのは「サービスが知らなくても成り立つAPI」に
// するため。サービス側に ?feed= の受け口を作らせると、RSSを使えるかどうかが
// サービスの実装に依存してしまう。
// =====================================================================

/** 公開ページ共通の外枠。JSを前提にしない(唯一の例外が ?view= の閲覧ページ)。 */
function publicPageOpen(string $title): void {
  header('Content-Type: text/html; charset=utf-8');
  header('Cache-Control: private, no-store');
  header('Referrer-Policy: no-referrer');
  header('X-Robots-Tag: noindex, nofollow');
  ?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="referrer" content="no-referrer" />
<meta name="robots" content="noindex, nofollow" />
<title><?php echo h($title); ?></title>
<style>
:root { color-scheme: light dark; --bg:#f7f7f8; --fg:#1b1b1f; --card:#fff; --line:#d8d8de; --muted:#5d5d68; --accent:#2f6fd0; --danger:#c03434; }
@media (prefers-color-scheme: dark) { :root { --bg:#16171a; --fg:#e8e8ec; --card:#1f2024; --line:#34353b; --muted:#a0a0ab; --accent:#6fa8ff; --danger:#ff8a8a; } }
* { box-sizing: border-box; }
body { margin:0; padding-block:24px; padding-inline:16px; background:var(--bg); color:var(--fg); font-family:system-ui,-apple-system,"Segoe UI","Hiragino Kaku Gothic ProN","Noto Sans JP",sans-serif; line-height:1.7; }
.wrap { max-width:760px; margin:0 auto; }
h1 { font-size:1.3rem; margin:0 0 4px; }
h2 { font-size:1.05rem; margin:0 0 8px; }
.sub { color:var(--muted); font-size:.88rem; margin:0 0 20px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; margin-bottom:16px; }
.note { color:var(--muted); font-size:.86rem; margin:6px 0; }
.state { display:inline-block; font-size:.78rem; border:1px solid var(--line); border-radius:999px; padding:1px 10px; margin-left:6px; vertical-align:middle; }
button { font:inherit; padding:6px 14px; border-radius:7px; border:1px solid var(--line); background:transparent; color:var(--fg); cursor:pointer; }
button.primary { border-color:var(--accent); color:var(--accent); }
button.danger { border-color:var(--danger); color:var(--danger); }
select { font:inherit; padding:5px 8px; border-radius:7px; border:1px solid var(--line); background:var(--card); color:var(--fg); }
form.inline { display:inline-block; margin:4px 6px 4px 0; }
code, .url { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:.82rem; word-break:break-all; }
.url { display:block; background:var(--bg); border:1px solid var(--line); border-radius:7px; padding:9px; margin:6px 0 10px; }
.inner { border-top:1px solid var(--line); margin-top:14px; padding-top:12px; }
.msg { border-left:3px solid var(--accent); padding:8px 12px; margin-bottom:16px; background:var(--card); }
.msg.bad { border-left-color:var(--danger); }
.warn { border:1px solid var(--danger); border-radius:8px; padding:10px 12px; margin:10px 0; }
table { width:100%; border-collapse:collapse; font-size:.86rem; }
th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
.scroll { overflow-x:auto; }
</style>
</head>
<body><div class="wrap">
<?php
}

function publicPageClose(): void {
  echo "</div></body>\n</html>\n";
  exit;
}

/** 見つからない/失効したトークンの返し方を1箇所に集める(区別させないため)。 */
function publicNotFound(string $message): void {
  http_response_code(404);
  header('Content-Type: text/plain; charset=utf-8');
  header('Cache-Control: no-store');
  echo $message . "\n";
  exit;
}

/** 鍵付きの閲覧URL。ここだけが &k= を付けてよい唯一の場所。 */
function feedViewUrlWithKey(string $token, string $keyB64): string {
  // 鍵は # の後ろ(フラグメント)に付きます。ここはサーバへ送られないので、
  // アクセスログにもRefererにも残りません。&k= を ? 側へ移さないこと。
  $url = publicBaseUrl() . '?view=1#t=' . rawurlencode($token);
  $raw = ($keyB64 === '') ? false : base64_decode($keyB64, true);

  if ($raw === false) {
    // 鍵が無い(open/notice)か、読めない。鍵なしのURLをそのまま使います。
    $withKey = $url;
  } else {
    $withKey = $url . '&k=' . base64UrlEncode($raw);
  }

  return $withKey;
}

function feedSubscribeUrl(string $token): string {
  $url = publicBaseUrl() . '?feed=' . rawurlencode($token);

  return $url;
}

// ---------------------------------------------------------------------
// ?feed=<token> … RSSリーダー(と閲覧ページ)が叩く口
// ---------------------------------------------------------------------

function publicServeFeed(string $token): void {
  $feed = feedFindByToken($token);
  if ($feed === null) {
    publicNotFound('feed not found');
  }

  $service = (string)($feed['service'] ?? '');
  $userid  = (string)($feed['userid'] ?? '');

  // 発行後にRSSチャンネルをdenyにした場合、既存のフィードもここで止まる。
  // 410 Gone にするのは、多くのリーダーがこれを「もう無い」と解釈して
  // 購読を畳んでくれるため(404だと一時障害と見て叩き続ける実装がある)。
  $rssState = channelState($service, $userid, CHANNEL_RSS);
  if (!channelAllowsDelivery($rssState)) {
    http_response_code(410);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    pushLog("feed: service={$service} userid={$userid} rssチャンネルが{$rssState}のため410で拒否");
    echo "this feed has been turned off by the user\n";
    exit;
  }

  $format = (string)($_GET['format'] ?? 'rss');
  $items  = inboxHistoryFor($service, $userid, FEED_ITEM_MAX);
  $etag   = feedEtag($feed, $items);
  $now    = time();

  header('ETag: ' . $etag);
  header('Referrer-Policy: no-referrer');
  header('X-Robots-Tag: noindex, nofollow');

  // openモードだけはフィードに本文そのものが載るため、中継にもブラウザにも
  // 残させない。notice/sealedは中身が無害なので条件付きGETを効かせる。
  if ((string)($feed['mode'] ?? '') === FEED_MODE_OPEN) {
    header('Cache-Control: private, no-store');
  } else {
    header('Cache-Control: private, max-age=0, must-revalidate');
  }

  if ($format === 'json') {
    // 閲覧ページ(人が開くページ)はレート制限の対象にしない。制限の目的は
    // 短い間隔で叩き続けるリーダーを抑えることで、人の再読み込みではない。
    // ここで304を返すと本文が空になり、閲覧ページ側がJSONを読めなくなる。
    feedTouch((string)($feed['feed_id'] ?? ''), $now);
    header('Content-Type: application/json; charset=utf-8');
    echo feedRenderJson($feed, $items, $token);
    exit;
  }

  $lastPoll = (int)($feed['last_poll'] ?? 0);
  if ($now - $lastPoll < FEED_MIN_POLL_SEC) {
    // レート制限。ここで feedTouch を呼んではいけない(理由は feedTouch のコメント)。
    http_response_code(304);
    exit;
  }

  $ifNoneMatch = trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? ''));
  feedTouch((string)($feed['feed_id'] ?? ''), $now);
  if ($ifNoneMatch !== '' && $ifNoneMatch === $etag) {
    http_response_code(304);
    exit;
  }

  header('Content-Type: application/rss+xml; charset=utf-8');
  pushLog('feed: service=' . $service . ' userid=' . $userid . ' mode=' . (string)($feed['mode'] ?? '') . ' items=' . count($items));
  echo feedRenderRss($feed, $items, $token);
  exit;
}

// ---------------------------------------------------------------------
// ?view=1 … sealedモードの閲覧ページ
//
// ここだけはJSが必須。WebCryptoで復号することそのものが目的の画面なので、
// JS無しで意味のあるHTMLは原理的に作れない。中身は全部JSが組み立てる。
// ---------------------------------------------------------------------

function publicServeViewer(): void {
  publicPageOpen('通知を読む');
  ?>
<h1>通知を読む</h1>
<p class="sub">フィードの内容をこの端末の中だけで復号して表示します。鍵はサーバへ送られません。</p>
<div id="out" class="card">読み込み中…</div>
<script>
(() => {
  'use strict';

  const out = document.getElementById('out');
  const show = (html) => { out.innerHTML = html; };
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  // 鍵とトークンはフラグメント(#以降)で受け取る。フラグメントはサーバへ
  // 送信されないため、アクセスログにも中継にも残らない。これがこの画面の
  // 存在理由そのものなので、クエリ(?)へ移してはいけない。
  const frag = new URLSearchParams(location.hash.replace(/^#/, ''));
  const token = frag.get('t') || '';
  const keyFromUrl = frag.get('k') || '';

  if (!token) {
    show('<p>このURLにはフィードの指定がありません。通知設定画面で発行した「閲覧URL」を開いてください。</p>');
    return;
  }

  const storeKey = 'pusyuuPushFeedKey:' + token.slice(0, 22);
  let key = keyFromUrl;
  if (key) {
    // 一度開けば以後はフラグメント無しでも読める(RSSリーダーのリンクから
    // 飛んできたときのため)。保存できない環境でも、その回は動く。
    try { localStorage.setItem(storeKey, key); } catch (e) { /* プライベートウィンドウ等 */ }
  } else {
    try { key = localStorage.getItem(storeKey) || ''; } catch (e) { key = ''; }
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
    return bytes;
  }
  function b64urlToBytes(s) {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    return b64ToBytes(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  }

  async function decrypt(keyBytes, cipherB64) {
    const raw = b64ToBytes(cipherB64);
    // PHP側の保存形式は IV(12) + TAG(16) + 暗号文 の順。WebCryptoは
    // 「暗号文の末尾に認証タグが付いている」ことを期待するので、ここで
    // 並べ替える。忘れるとエラーメッセージも出ないまま必ず失敗するため、
    // 「復号だけが通らない」ときは真っ先にここを疑うこと。
    const iv = raw.slice(0, 12);
    const tag = raw.slice(12, 28);
    const body = raw.slice(28);
    const data = new Uint8Array(body.length + tag.length);
    data.set(body, 0);
    data.set(tag, body.length);

    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, cryptoKey, data);
    return JSON.parse(new TextDecoder().decode(plain));
  }

  function when(sec) {
    if (!sec) { return ''; }
    return new Date(sec * 1000).toLocaleString('ja-JP');
  }

  fetch('?feed=' + encodeURIComponent(token) + '&format=json', { credentials: 'omit' })
    .then((r) => { if (!r.ok) { throw new Error('http ' + r.status); } return r.json(); })
    .then(async (data) => {
      const items = data.items || [];
      if (items.length === 0) {
        show('<p>いまのところ通知はありません。</p>');
        return;
      }

      const needsKey = items.some((it) => it.cipher);
      if (needsKey && !key) {
        show('<p>このフィードは暗号化されています。この端末には鍵がありません。</p>'
           + '<p class="note">発行したときに表示された「閲覧URL」(#k= を含むもの)を開いてください。鍵はサーバに預けられていないため、こちらから送ることはできません。</p>');
        return;
      }

      let keyBytes = null;
      if (needsKey) {
        try { keyBytes = b64urlToBytes(key); } catch (e) { keyBytes = null; }
        if (!keyBytes || keyBytes.length !== 32) {
          show('<p>鍵の形式が正しくありません。閲覧URLをもう一度開き直してください。</p>');
          return;
        }
      }

      const parts = [];
      for (const item of items) {
        if (!item.cipher) {
          parts.push('<div class="card"><h2>' + esc(item.title) + '</h2>'
            + '<p class="note">' + esc(when(item.created)) + '</p>'
            + '<p>' + esc(item.body) + '</p>'
            + (item.link ? '<p><a href="' + esc(item.link) + '">開く</a></p>' : '') + '</div>');
          continue;
        }
        try {
          const plain = await decrypt(keyBytes, item.cipher);
          parts.push('<div class="card"><h2>' + esc(plain.title) + '</h2>'
            + '<p class="note">' + esc(when(plain.created || item.created)) + '</p>'
            + '<p>' + esc(plain.body) + '</p>'
            + (plain.url ? '<p><a href="' + esc(plain.url) + '">開く</a></p>' : '') + '</div>');
        } catch (e) {
          parts.push('<div class="card"><h2>復号できませんでした</h2>'
            + '<p class="note">鍵が別のフィードのものである可能性があります。</p></div>');
        }
      }
      out.outerHTML = parts.join('\n');
    })
    .catch((e) => {
      show('<p>フィードを読み込めませんでした。</p><p class="note">' + esc(e && e.message ? e.message : e) + '</p>');
    });
})();
</script>
<?php
  publicPageClose();
}

// ---------------------------------------------------------------------
// ?ui=<ticket> … 通知設定画面
//
// サービス側が用意するのは「この画面へのリンク1本」だけ。チャンネルの
// 切り替えもフィードの発行・失効も、ここで完結する。JSは一切使わない
// (全部ただのPOSTフォーム)。
// ---------------------------------------------------------------------

function settingsChannelLabel(string $channel): string {
  if ($channel === CHANNEL_PUSH) {
    $label = 'プッシュ通知';
  } else if ($channel === CHANNEL_RSS) {
    $label = 'RSSでの通知';
  } else if ($channel === CHANNEL_DESKTOP) {
    $label = 'デスクトップ通知';
  } else {
    $label = $channel;
  }

  return $label;
}

function settingsChannelDescription(string $channel): string {
  if ($channel === CHANNEL_PUSH) {
    $text = 'ブラウザを閉じていても届きます。OSのプッシュサービス(Chromeなら Google、Firefoxなら Mozilla)を経由します。';
  } else if ($channel === CHANNEL_RSS) {
    $text = 'お使いのRSSリーダーが定期的に取りに来ます。プッシュ通知が使えない環境向けの受け取り方です。';
  } else if ($channel === CHANNEL_DESKTOP) {
    $text = 'ページを開いている間だけ、ブラウザの通知として表示します。ブラウザ側の許可とは別に、ここで出す / 出さないを決められます。';
  } else {
    $text = '';
  }

  return $text;
}

function settingsStateLabel(string $state): string {
  if ($state === CHANNEL_UNSET) {
    $label = 'まだ選んでいません';
  } else if ($state === CHANNEL_ALLOW) {
    $label = '使う';
  } else if ($state === CHANNEL_DENY) {
    $label = '使わない(錠)';
  } else {
    $label = $state;
  }

  return $label;
}

/**
 * カードの見出しに出す「いま実際にどうなっているか」。
 *
 * 【なぜ設定値(allow/deny)をそのまま出さないか】プッシュは「使う」にしていても、
 * 端末が1台も登録されていなければ1通も届かない。設定値だけを見出しに出すと、
 * 何も届かない状態を「使う」と表示することになり、画面が嘘をつく。
 * 設定値は「使ってよいかどうか」しか表していないので、見出しには検証できる事実
 * (登録台数・発行済みフィード本数)の方を出す。
 *
 * デスクトップだけは、サーバ側にブラウザの許可状況が分からない。分からないことを
 * 分かったように書かない、という理由でここは断定しない書き方にしてある。
 */
function settingsChannelStatusLabel(string $channel, string $state, int $subCount, int $feedCount): string {
  if ($state === CHANNEL_DENY) {
    $label = '使わない';
  } else if ($channel === CHANNEL_PUSH) {
    $label = $subCount > 0 ? '受信中(' . $subCount . '台)' : '端末が未登録';
  } else if ($channel === CHANNEL_RSS) {
    $label = $feedCount > 0 ? '配信中(' . $feedCount . '本)' : 'フィード未発行';
  } else if ($channel === CHANNEL_DESKTOP) {
    // サーバにはブラウザの許可状況が分かりません。分からないことを断定しません。
    $label = '端末側の許可しだい';
  } else {
    $label = settingsStateLabel($state);
  }

  return $label;
}


function settingsFeedModeLabel(string $mode): string {
  if ($mode === FEED_MODE_OPEN) {
    $label = '本文を載せる(手元のリーダー向け)';
  } else if ($mode === FEED_MODE_NOTICE) {
    $label = '新着があることだけ載せる';
  } else if ($mode === FEED_MODE_SEALED) {
    $label = '本文を暗号化して載せる';
  } else {
    $label = $mode;
  }

  return $label;
}

/**
 * フィードの発行フォームと一覧。RSSチャンネルのカードの「中」に置く。
 *
 * 【なぜ独立したカードにしないか】「RSSを使うかどうか」と「どのフィードを
 * 発行しているか」は同じ1つの設定なので、画面上で離すと片方だけ見て判断して
 * しまう(「使う」にしただけで届くと思う、あるいは発行済みの存在に気づかない)。
 * 他の2チャンネルには発行に相当する操作が無いので、ここだけ中身が厚くなる。
 */
function settingsRenderFeedBlock(array $feeds, string $selfUrl, bool $rssAllowed): void {
  ?>
  <div class="inner">
<?php if (!$rssAllowed): ?>
    <p class="note">「使わない」の間は、新しいフィードを発行できません。</p>
<?php if (count($feeds) > 0): ?>
    <p class="note">発行済みのフィード<?php echo count($feeds); ?>本は配信が止まっています(リーダー側にはエラーとして見えます)。</p>
<?php endif; ?>
<?php else: ?>
    <p class="note">どれを選ぶかは「お使いのRSSリーダーをどれくらい信用しているか」の表明です。自分のPCの中だけで動くリーダー(Thunderbird等)なら本文を載せても漏れませんが、クラウドのリーダー(Feedly等)はフィードの中身をその会社のサーバに保存します。</p>
    <form method="post" action="<?php echo h($selfUrl); ?>">
      <input type="hidden" name="op" value="feed_create" />
      <select name="mode">
<?php foreach (FEED_MODE_ALL as $mode): ?>
        <option value="<?php echo h($mode); ?>"<?php echo $mode === FEED_MODE_DEFAULT ? ' selected' : ''; ?>><?php echo h(settingsFeedModeLabel($mode)); ?></option>
<?php endforeach; ?>
      </select>
      <button type="submit" class="primary">フィードを発行する</button>
    </form>
    <p class="note">暗号化を選んだ場合、RSSリーダーの画面には読めない文字列が並びます。中身は発行時に表示される「閲覧URL」を開いたときだけ読めます。</p>

<?php if (count($feeds) === 0): ?>
    <p class="note">いまは1本も発行していません。発行するまで、RSSで通知が届くことはありません。</p>
<?php else: ?>
    <div class="scroll">
    <table>
      <tr><th>種類</th><th>発行</th><th>最終取得</th><th></th></tr>
<?php foreach ($feeds as $feed): ?>
      <tr>
        <td><?php echo h(settingsFeedModeLabel((string)($feed['mode'] ?? ''))); ?></td>
        <td><?php echo h(date('Y-m-d', (int)($feed['created'] ?? 0))); ?></td>
        <td><?php echo (int)($feed['last_poll'] ?? 0) === 0 ? 'まだありません' : h(date('Y-m-d H:i', (int)$feed['last_poll'])); ?></td>
        <td>
          <form class="inline" method="post" action="<?php echo h($selfUrl); ?>">
            <input type="hidden" name="op" value="feed_revoke" />
            <input type="hidden" name="feed_id" value="<?php echo h((string)($feed['feed_id'] ?? '')); ?>" />
            <button type="submit" class="danger">失効</button>
          </form>
        </td>
      </tr>
<?php endforeach; ?>
    </table>
    </div>
    <p class="note">「最終取得」が空のままなら、リーダーはまだ一度も取りに来ていません。URLの登録に失敗している可能性があります。</p>
<?php endif; ?>
<?php endif; ?>
  </div>
<?php
}

function publicServeSettings(string $ui): void {
  // 1) チケットで来た場合は、その場でCookieへ引き換えてURLからチケットを消す。
  //    チケットは一度きり。詳しくは SETTINGS_TICKET_TTL のコメント。
  if ($ui !== '' && $ui !== '1') {
    $ticketClaims = settingsVerifyToken($ui, 'ticket');
    if ($ticketClaims !== null && settingsTicketConsume($ui, (int)$ticketClaims['exp'])) {
      $cookie = settingsCookieIssue($ticketClaims);
      if ($cookie !== null) {
        $host = strtolower((string)strtok((string)($_SERVER['HTTP_HOST'] ?? ''), ':'));
        $secure = !($host === 'localhost' || $host === '127.0.0.1' || $host === '::1');
        // SameSite=Lax: サービス(別サイト)からのリンクで飛んできた通常の画面遷移では
        // 送られ、フォーム送信はこの画面自身からなので同一サイト扱いになる。
        setcookie(SETTINGS_COOKIE_NAME, $cookie, [
          'expires'  => time() + SETTINGS_COOKIE_TTL,
          'path'     => settingsCookiePath(),
          'secure'   => $secure,
          'httponly' => true,
          'samesite' => 'Lax',
        ]);
      }
      header('Location: ' . publicBaseUrl() . '?ui=1');
      exit;
    }
    // 署名が合わない・期限切れ・既に使われた。下の期限切れ表示へ落ちる。
  }

  // 2) 以降はCookieで本人を判断する。
  $claims = settingsVerifyToken((string)($_COOKIE[SETTINGS_COOKIE_NAME] ?? ''), 'session');
  if ($claims === null) {
    publicPageOpen('通知設定');
    echo '<h1>通知設定</h1><div class="card"><p>このリンクはもう使えません。</p>'
       . '<p class="note">通知設定を開くためのリンクは<strong>一度きり</strong>で、'
       . (int)(SETTINGS_TICKET_TTL / 60) . '分で期限切れになります。'
       . 'アドレスをコピーしても、別のブラウザやプライベートウィンドウでは開けません。</p>'
       . '<p class="note">サービスの画面からもう一度「通知設定」を開き直してください。'
       . 'ブラウザがこのサイトのCookieを拒否している場合も、ここに来ます。</p></div>';
    publicPageClose();
  }

  $service   = $claims['service'];
  $userid    = $claims['userid'];
  $returnUrl = (string)$claims['return'];

  $message = '';
  $messageBad = false;
  $issued = null; // 発行直後の一度きりの表示

  if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $op = (string)($_POST['op'] ?? '');

    // この画面が扱うのはRSSだけ。
    //
    // 【なぜプッシュ/デスクトップをここに置かないか】あの2つは、ブラウザの通知許可と
    // 購読という「そのオリジンでしか出来ない操作」と必ずセットになる。別オリジンの
    // この画面に切り替えだけを置くと、押しても実際には何も起きない半端なスイッチに
    // なる(実際にそうなって、0台のまま「使う」と表示される状態を作ってしまった)。
    // あの2つはサービス自身の画面でトグルし、その裏で channels_set を呼ぶのが正しい。
    // RSSにはブラウザ側の操作が無く、しかもフィードのURLを表示する場所が要るので、
    // ここに置くのが自然、という切り分け。
    if ($op === 'channel') {
      $state = (string)($_POST['state'] ?? '');
      if (!isKnownChannelState($state)) {
        $message = '不明な操作です。';
        $messageBad = true;
      } else {
        channelSetState($service, $userid, CHANNEL_RSS, $state, $service . ' (RSS設定画面)');
        $message = 'RSSでの通知を「' . settingsStateLabel($state) . '」にしました。';

        // 「使わない」にしたら発行済みのフィードもその場で失効させる。残したまま
        // 止めることもできるが、利用者から見て「使わないと言ったのにURLが生きている」
        // 状態は約束を破っているように見える。
        if ($state === CHANNEL_DENY) {
          $removed = feedRevokeAllFor($service, $userid);
          if ($removed > 0) { $message .= ' 発行済みのフィード' . $removed . '本も失効させました。'; }
        }
      }
    } elseif ($op === 'feed_create') {
      $mode = (string)($_POST['mode'] ?? FEED_MODE_DEFAULT);
      if (!in_array($mode, FEED_MODE_ALL, true)) {
        $message = '不明なモードです。';
        $messageBad = true;
      } elseif (!channelAllowsDelivery(channelState($service, $userid, CHANNEL_RSS))) {
        $message = 'RSSでの通知は「使わない」になっています。先に「使う」へ戻してください。';
        $messageBad = true;
      } else {
        $created = feedCreate($service, $userid, $mode);
        if (!empty($created['ok'])) {
          $issued = $created;
          $message = 'フィードを発行しました。下のURLはこの画面でしか表示できません。';
        } elseif (($created['error'] ?? '') === 'too_many_feeds') {
          $message = 'フィードは1人あたり' . FEED_MAX_PER_USER . '本までです。使っていないものを失効させてください。';
          $messageBad = true;
        } else {
          $message = 'フィードを発行できませんでした。';
          $messageBad = true;
        }
      }
    } elseif ($op === 'feed_revoke') {
      $feedId = (string)($_POST['feed_id'] ?? '');
      if (feedRevoke($service, $userid, $feedId)) {
        $message = 'フィードを失効させました。このURLはもう使えません。';
      } else {
        $message = '対象のフィードが見つかりませんでした。';
        $messageBad = true;
      }
    } else {
      $message = '不明な操作です。';
      $messageBad = true;
    }
  }

  $rssState = channelState($service, $userid, CHANNEL_RSS);
  $feeds    = feedsFor($service, $userid);
  $audit    = channelAuditFor($service, $userid);
  // URLにチケットは残さない(Cookieで本人が分かっているので不要)。
  $selfUrl  = publicBaseUrl() . '?ui=1';

  publicPageOpen($service . ' のRSS通知設定');
  ?>
<h1><?php echo h($service); ?> のRSS通知設定</h1>
<p class="sub">プッシュ通知を受け取れない環境向けに、RSSリーダーで通知を受け取るための設定です。プッシュ通知とデスクトップ通知は <?php echo h($service); ?> の設定画面で切り替えます。<?php if ($returnUrl !== ''): ?> <a href="<?php echo h($returnUrl); ?>"><?php echo h($service); ?> に戻る</a><?php endif; ?></p>

<?php if ($message !== ''): ?>
<div class="msg<?php echo $messageBad ? ' bad' : ''; ?>"><?php echo h($message); ?></div>
<?php endif; ?>

<?php if ($issued !== null): ?>
<div class="card">
  <h2>発行したフィード</h2>
  <div class="warn">
    <strong>この2つのURLは、この画面を閉じると二度と表示できません。</strong>
    <p class="note">サーバはトークンをそのままでは保存していないため、あとから取り出すことができません。必要なら今すぐ控えてください。</p>
  </div>
  <p><strong>RSSリーダーに登録するURL</strong></p>
  <span class="url"><?php echo h(feedSubscribeUrl((string)$issued['token'])); ?></span>
<?php if ((string)$issued['key_b64'] !== ''): ?>
  <p><strong>自分用の閲覧URL(ブックマークしてください)</strong></p>
  <span class="url"><?php echo h(feedViewUrlWithKey((string)$issued['token'], (string)$issued['key_b64'])); ?></span>
  <p class="note">復号の鍵は「#」より後ろに入っています。この部分はブラウザからサーバへ送られないため、こちらには残りません。だからこそ、失くすと読めなくなります。</p>
<?php endif; ?>
</div>
<?php endif; ?>

<div class="card">
  <h2>RSSでの通知<span class="state"><?php echo h(settingsChannelStatusLabel(CHANNEL_RSS, $rssState, 0, count($feeds))); ?></span></h2>
  <p class="note"><?php echo h(settingsChannelDescription(CHANNEL_RSS)); ?></p>
<?php if ($rssState === CHANNEL_DENY): ?>
  <p class="note">「使わない」にしている間は、新しいフィードを発行できません。押し間違いで有効になることを防ぐための状態です。</p>
  <form class="inline" method="post" action="<?php echo h($selfUrl); ?>">
    <input type="hidden" name="op" value="channel" />
    <input type="hidden" name="state" value="<?php echo h(CHANNEL_ALLOW); ?>" />
    <button type="submit" class="primary">使う</button>
  </form>
<?php else: ?>
  <form class="inline" method="post" action="<?php echo h($selfUrl); ?>">
    <input type="hidden" name="op" value="channel" />
    <input type="hidden" name="state" value="<?php echo h(CHANNEL_DENY); ?>" />
    <button type="submit" class="danger">使わない</button>
  </form>
<?php endif; ?>
<?php settingsRenderFeedBlock($feeds, $selfUrl, channelAllowsDelivery($rssState)); ?>
</div>

<?php if (count($audit) > 0): ?>
<div class="card">
  <h2>設定が変更された記録</h2>
  <p class="note">身に覚えのない変更が無いか確認できます。</p>
  <div class="scroll">
  <table>
    <tr><th>日時</th><th>対象</th><th>変更後</th><th>経由</th></tr>
<?php foreach ($audit as $entry): ?>
    <tr>
      <td><?php echo h(date('Y-m-d H:i', (int)($entry['at'] ?? 0))); ?></td>
      <td><?php echo h(settingsChannelLabel((string)($entry['channel'] ?? ''))); ?></td>
      <td><?php echo h(settingsStateLabel((string)($entry['state'] ?? ''))); ?></td>
      <td><?php echo h((string)($entry['by'] ?? '')); ?></td>
    </tr>
<?php endforeach; ?>
  </table>
  </div>
</div>
<?php endif; ?>
<?php
  publicPageClose();
}

// ---------------------------------------------------------------------
// 入力の取り出し
// ---------------------------------------------------------------------

function inputStr(array $input, string $key, string $default = ''): string {
  $value = $input[$key] ?? $default;
  return is_string($value) ? $value : $default;
}

// ---------------------------------------------------------------------
// 公開ルートの振り分け
//
// 合言葉を要求するJSON APIより前に処理する。これらはJSONを返さないので、
// Content-Typeもそれぞれの出口で送っている(このファイル冒頭でJSONヘッダを
// 送らなくなったのはそのため)。いずれも呼ばれれば内部で exit する。
// ---------------------------------------------------------------------

if (isset($_GET['feed']) && is_string($_GET['feed'])) { publicServeFeed($_GET['feed']); }
if (isset($_GET['view'])) { publicServeViewer(); }
if (isset($_GET['ui']) && is_string($_GET['ui'])) { publicServeSettings($_GET['ui']); }

// ---------------------------------------------------------------------
// ここから先は合言葉つきのJSON API(サービスからのサーバ間呼び出し)
// ---------------------------------------------------------------------

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$input = $_POST;
if (empty($input)) {
  $rawBody = file_get_contents('php://input');
  if ($rawBody !== false && trim($rawBody) !== '') {
    $decoded = json_decode($rawBody, true);
    if (is_array($decoded)) { $input = $decoded; }
  }
}

$action = (string)($_GET['api'] ?? '');
requireSecret($input);

// ---------------------------------------------------------------------
// アクション振り分け
// ---------------------------------------------------------------------

switch ($action) {

  case 'selftest': {
    $keys = vapidKeys();
    respond(true, [
      'vapid_ready'      => $keys !== null,
      'vapid_public_key' => $keys['public_raw_b64url'] ?? null,
      'storage_writable' => is_dir(STORAGE_DIR) ? is_writable(STORAGE_DIR) : is_writable(dirname(STORAGE_DIR)),
      'openssl'          => extension_loaded('openssl'),
      'php_version'      => PHP_VERSION,
      // 追加機能ぶんの疎通確認。「設定画面のURLが http:// になっていないか」
      // 「フィードの暗号化が実際に通るか」をここで一度に見られるようにしておく。
      'public_base_url'  => publicBaseUrl(),
      'channels'         => CHANNEL_ALL,
      'feed_modes'       => FEED_MODE_ALL,
      'aes_gcm_ok'       => pusyuuPushAesGcmDecrypt((string)pusyuuPushAesGcmEncrypt('ok', str_repeat("\x01", 32)), str_repeat("\x01", 32)) === 'ok',
      'storage_key_ready' => pusyuuPushStorageKey() !== null,
    ]);
  }

  case 'vapid_public_key': {
    $keys = vapidKeys();
    if ($keys === null) { fail('server_misconfigured', 'VAPID鍵を用意できませんでした。', 500); }
    respond(true, ['public_key' => $keys['public_raw_b64url']]);
  }

  case 'subscribe': {
    $service = inputStr($input, 'service');
    $userid  = inputStr($input, 'userid');
    $subJson = inputStr($input, 'subscription');
    if ($service === '' || $userid === '' || $subJson === '') {
      fail('invalid_input', 'service・userid・subscriptionは必須です。');
    }
    $subscription = json_decode($subJson, true);
    if (!is_array($subscription)) {
      fail('invalid_input', 'subscriptionの形式が不正です。');
    }
    // 登録時のゲート。サービスがチャンネルという概念を知らなくても、
    // 「使わない」と言った利用者のところで勝手に有効化されない。
    $pushState = channelState($service, $userid, CHANNEL_PUSH);
    if (!channelAllowsDelivery($pushState)) {
      pushLog("subscribe拒否: service={$service} userid={$userid} pushチャンネルが{$pushState}");
      fail('channel_denied', 'この利用者はプッシュ通知を使わない設定にしています。', 403);
    }
    if (!upsertSubscription($service, $userid, $subscription, inputStr($input, 'ua'))) {
      pushLog("subscribe失敗: service={$service} userid={$userid}(subscriptionにendpoint/keysが揃っていない)");
      fail('invalid_input', 'subscriptionにendpoint・keys.p256dh・keys.authが揃っていません。');
    }
    $endpointHost = parse_url((string)($subscription['endpoint'] ?? ''), PHP_URL_HOST) ?: '?';
    pushLog("subscribe成功: service={$service} userid={$userid} endpoint_host={$endpointHost}");
    respond(true, []);
  }

  case 'unsubscribe': {
    $service = inputStr($input, 'service');
    $userid  = inputStr($input, 'userid');
    $endpoint = inputStr($input, 'endpoint');
    if ($service === '' || $userid === '' || $endpoint === '') {
      fail('invalid_input', 'service・userid・endpointは必須です。');
    }
    removeSubscription($service, $userid, $endpoint);
    pushLog("unsubscribe: service={$service} userid={$userid}");
    respond(true, []);
  }

  case 'send': {
    $startedAt = microtime(true);
    $service = inputStr($input, 'service');
    $userid  = inputStr($input, 'userid');
    $title   = inputStr($input, 'title');
    $body    = inputStr($input, 'body');
    $url     = inputStr($input, 'url');
    $tag     = inputStr($input, 'tag');
    $icon    = inputStr($input, 'icon');
    if ($service === '' || $userid === '' || $title === '') {
      fail('invalid_input', 'service・userid・titleは必須です。');
    }

    // inboxへの追記はチャンネルの状態に関わらず必ず行う。inboxは「通知の実体」、
    // チャンネルは「それをどの経路で外へ出してよいか」で、層が違うため。
    // サービス自身の画面(ログイン済みで見る未読一覧)はチャンネルの話ではない。
    appendInbox($service, $userid, $title, $body, $url, $tag !== '' ? $tag : null, $icon !== '' ? $icon : null);

    $channelStates = channelStatesFor($service, $userid);
    $pushState = $channelStates[CHANNEL_PUSH];

    $subs = [];
    $pushed = 0;
    $pruned = 0;
    $statusLog = [];
    if (channelAllowsDelivery($pushState)) {
      $subs = subscriptionsFor($service, $userid);
      foreach ($subs as $sub) {
        $status = sendPushToSubscription($sub);
        $endpointHost = parse_url((string)($sub['endpoint'] ?? ''), PHP_URL_HOST) ?: '?';
        $statusLog[] = "{$endpointHost}=" . ($status ?? 'unreachable');
        if ($status !== null && $status >= 200 && $status < 300) {
          $pushed++;
        } elseif ($status === 404 || $status === 410) {
          removeSubscription($service, $userid, (string)($sub['endpoint'] ?? ''));
          $pruned++;
        }
      }
    }

    $elapsedMs = (int)round((microtime(true) - $startedAt) * 1000);
    if (!channelAllowsDelivery($pushState)) {
      pushLog("send: service={$service} userid={$userid} pushチャンネルが{$pushState}のため配送せずinboxへの追記のみ({$elapsedMs}ms)");
    } elseif (empty($subs)) {
      // 「通知が来ない」の原因切り分けで最も多いのはこれ(購読自体が0件、
      // つまりブラウザ側で購読ボタンを押していない/押しても失敗している)なので、
      // 個別に分かるようにしておく。
      pushLog("send: service={$service} userid={$userid} 購読が0件のためinboxへの追記のみ({$elapsedMs}ms)");
    } else {
      pushLog("send: service={$service} userid={$userid} pushed={$pushed} pruned={$pruned} 内訳=[" . implode(', ', $statusLog) . "] ({$elapsedMs}ms)");
    }

    // pushed/prunedは従来どおり。channelsは追加情報で、知らないサービスは
    // 無視すればよい(既存の呼び出し側は1行も変えなくてよい)。
    respond(true, ['pushed' => $pushed, 'pruned' => $pruned, 'channels' => $channelStates]);
  }

  // -------------------------------------------------------------------
  // ブロードキャスト(宛先が特定の1人ではない通知)
  //
  // 「お知らせを追加した」「新しいスレッドが立った」のように、相手が1人に
  // 決まらない通知のための口。このAPIは本来 (service, userid) 宛ての設計なので、
  // 宛先を「そのサービスで購読かフィードを持っている人全員」に読み替えて、
  // 1人ずつのinboxへ同じ内容を積む。
  //
  // 【なぜ共有の擬似useridで済ませないか】全員が同じuseridを使うと、誰か1人が
  // ackした瞬間に全員のぶんが既読になり、残りの人には二度と表示されない。
  // inboxは1人ずつ持たせる必要がある。
  // -------------------------------------------------------------------

  case 'broadcast': {
    $startedAt = microtime(true);
    $service = inputStr($input, 'service');
    $title   = inputStr($input, 'title');
    $body    = inputStr($input, 'body');
    $url     = inputStr($input, 'url');
    $tag     = inputStr($input, 'tag');
    $icon    = inputStr($input, 'icon');
    if ($service === '' || $title === '') {
      fail('invalid_input', 'service・titleは必須です。');
    }

    $recipients = broadcastRecipients($service);
    if (empty($recipients)) {
      pushLog("broadcast: service={$service} 受け取り手が0人のため何もしませんでした。");
      respond(true, ['recipients' => 0, 'pushed' => 0, 'pruned' => 0, 'deferred' => 0]);
    }

    $queued = appendInboxBroadcast($service, $recipients, $title, $body, $url, $tag !== '' ? $tag : null, $icon !== '' ? $icon : null);

    // プッシュ配送。締め切りを過ぎたら残りは送らない(理由は
    // BROADCAST_PUSH_DEADLINE_SEC のコメント)。送らなかったぶんも inbox には
    // 入っているので、消えるわけではない。
    $deadline = $startedAt + BROADCAST_PUSH_DEADLINE_SEC;
    $pushed = 0;
    $pruned = 0;
    $deferred = 0;

    // channels.jsonl と subscriptions.jsonl は人数ぶん読み直さず、先に1回だけ
    // 読んで引き当てられる形にしておく(readJsonlは毎回ファイルを復号するため、
    // ループの中で呼ぶと人数の二乗に近い読み込みになる)。
    $pushStates = [];
    foreach (readJsonl(CHANNELS_FILE) as $row) {
      if (($row['service'] ?? '') !== $service || ($row['channel'] ?? '') !== CHANNEL_PUSH) { continue; }
      $pushStates[(string)($row['userid'] ?? '')] = (string)($row['state'] ?? CHANNEL_UNSET);
    }
    $subsByUser = [];
    foreach (readJsonl(SUBSCRIPTIONS_FILE) as $row) {
      if (($row['service'] ?? '') !== $service) { continue; }
      $subsByUser[(string)($row['userid'] ?? '')][] = $row;
    }

    foreach ($recipients as $userid) {
      if (!channelAllowsDelivery($pushStates[$userid] ?? CHANNEL_UNSET)) { continue; }
      foreach ($subsByUser[$userid] ?? [] as $sub) {
        if (microtime(true) >= $deadline) { $deferred++; continue; }
        $status = sendPushToSubscription($sub);
        if ($status !== null && $status >= 200 && $status < 300) {
          $pushed++;
        } elseif ($status === 404 || $status === 410) {
          removeSubscription($service, $userid, (string)($sub['endpoint'] ?? ''));
          $pruned++;
        }
      }
    }

    $elapsedMs = (int)round((microtime(true) - $startedAt) * 1000);
    pushLog("broadcast: service={$service} 宛先={$queued}人 pushed={$pushed} pruned={$pruned} 締め切り超過={$deferred} ({$elapsedMs}ms)");
    respond(true, ['recipients' => $queued, 'pushed' => $pushed, 'pruned' => $pruned, 'deferred' => $deferred]);
  }

  case 'inbox': {
    $service = inputStr($input, 'service');
    $userid  = inputStr($input, 'userid');
    $channel = inputStr($input, 'channel');

    // channelは省略可。省略時は従来どおり素の未読一覧を返す(サービス自身の
    // 画面用)。desktop等を指定した場合だけ、そのチャンネルのゲートがかかる。
    if ($channel !== '') {
      if (!isKnownChannel($channel)) {
        fail('invalid_input', '不明なチャンネルです。');
      }
      $state = channelState($service, $userid, $channel);
      if (!channelAllowsDelivery($state)) {
        pushLog("inbox: service={$service} userid={$userid} channel={$channel} が{$state}のため空を返却");
        respond(true, ['items' => [], 'channel' => $channel, 'channel_state' => $state]);
      }
    }

    $items = inboxFor($service, $userid);
    pushLog("inbox: service={$service} userid={$userid} items=" . count($items));
    respond(true, ['items' => $items]);
  }

  case 'ack': {
    $service = inputStr($input, 'service');
    $userid  = inputStr($input, 'userid');
    $idsRaw  = $input['ids'] ?? [];
    $ids     = is_array($idsRaw) ? array_values(array_filter($idsRaw, 'is_string')) : [];
    ackInbox($service, $userid, $ids);
    respond(true, []);
  }

  // -------------------------------------------------------------------
  // 通知チャンネル
  //
  // サービスはこれらを呼ばなくてもよい(呼ばない場合でもゲートは効く)。
  // 自前の設定画面を作りたいサービスだけが使う。
  // -------------------------------------------------------------------

  case 'channels_get': {
    $service = inputStr($input, 'service');
    $userid  = inputStr($input, 'userid');
    if ($service === '' || $userid === '') {
      fail('invalid_input', 'service・useridは必須です。');
    }
    respond(true, [
      'channels'      => channelStatesFor($service, $userid),
      'subscriptions' => count(subscriptionsFor($service, $userid)),
      'feeds'         => count(feedsFor($service, $userid)),
      'audit'         => channelAuditFor($service, $userid),
    ]);
  }

  case 'channels_set': {
    $service = inputStr($input, 'service');
    $userid  = inputStr($input, 'userid');
    $channel = inputStr($input, 'channel');
    $state   = inputStr($input, 'state');
    $purge   = inputStr($input, 'purge') === '1';
    if ($service === '' || $userid === '') {
      fail('invalid_input', 'service・useridは必須です。');
    }
    if (!isKnownChannel($channel)) {
      fail('invalid_input', '不明なチャンネルです。指定できるのは ' . implode(' / ', CHANNEL_ALL) . ' です。');
    }
    if (!isKnownChannelState($state)) {
      fail('invalid_input', '不明な状態です。指定できるのは ' . implode(' / ', [CHANNEL_UNSET, CHANNEL_ALLOW, CHANNEL_DENY]) . ' です。');
    }

    channelSetState($service, $userid, $channel, $state, $service);

    // 実体を残したまま止めるか、片付けるかは呼び出し側が選ぶ。
    // 「使わないと言ったのに登録が残っている」状態を避けたいならpurge=1。
    $purged = 0;
    if ($purge && $state === CHANNEL_DENY && $channel === CHANNEL_RSS) {
      $purged = feedRevokeAllFor($service, $userid);
    }
    if ($purge && $state === CHANNEL_DENY && $channel === CHANNEL_PUSH) {
      foreach (subscriptionsFor($service, $userid) as $sub) {
        removeSubscription($service, $userid, (string)($sub['endpoint'] ?? ''));
        $purged++;
      }
    }

    pushLog("channels_set: service={$service} userid={$userid} channel={$channel} state={$state} purged={$purged}");
    respond(true, ['channels' => channelStatesFor($service, $userid), 'purged' => $purged]);
  }

  // -------------------------------------------------------------------
  // 通知設定画面への入口
  //
  // サービスがこのAPIに対してすべきことは、原理的にこれ1つだけ。返ってきた
  // URLへリンクを1本張れば、チャンネルの切り替えもフィードの発行もこのAPIの
  // 中で完結する。「利用者が本人であること」だけをサービスから借りている。
  // -------------------------------------------------------------------

  case 'settings_ticket': {
    $service   = inputStr($input, 'service');
    $userid    = inputStr($input, 'userid');
    // return_url は省略可。渡すと「サービスに戻る」リンクが出るのに加えて、
    // プッシュ/デスクトップの「使う」がそのサービスの画面へ送り出す形になり、
    // ブラウザの通知許可をその場で取れるようになる(別オリジンの制約のため、
    // 許可の取得だけはサービス自身のページでしか行えない)。
    $returnUrl = inputStr($input, 'return_url');
    if ($service === '' || $userid === '') {
      fail('invalid_input', 'service・useridは必須です。');
    }
    if ($returnUrl !== '' && settingsValidReturnUrl($returnUrl) === '') {
      fail('invalid_input', 'return_urlはhttp(s)の絶対URLで指定してください。');
    }
    $ticket = settingsTicketIssue($service, $userid, $returnUrl);
    if ($ticket === null) {
      fail('server_misconfigured', 'チケットを発行できませんでした(共有鍵ファイルを読み込めません)。', 500);
    }
    respond(true, [
      'url'        => publicBaseUrl() . '?ui=' . rawurlencode($ticket),
      'expires_in' => SETTINGS_TICKET_TTL,
    ]);
  }

  // -------------------------------------------------------------------
  // RSSフィード
  //
  // 設定画面(?ui=)からも同じ関数を使うので、こちらは「サービスが自前の
  // 設定画面を持ちたい場合」のための口。使わなくても機能は成立する。
  // -------------------------------------------------------------------

  case 'feed_create': {
    $service = inputStr($input, 'service');
    $userid  = inputStr($input, 'userid');
    $mode    = inputStr($input, 'mode', FEED_MODE_DEFAULT);
    if ($service === '' || $userid === '') {
      fail('invalid_input', 'service・useridは必須です。');
    }
    if (!in_array($mode, FEED_MODE_ALL, true)) {
      fail('invalid_input', '不明なモードです。指定できるのは ' . implode(' / ', FEED_MODE_ALL) . ' です。');
    }
    $rssState = channelState($service, $userid, CHANNEL_RSS);
    if (!channelAllowsDelivery($rssState)) {
      pushLog("feed_create拒否: service={$service} userid={$userid} rssチャンネルが{$rssState}");
      fail('channel_denied', 'この利用者はRSSでの通知を使わない設定にしています。', 403);
    }

    $created = feedCreate($service, $userid, $mode);
    if (empty($created['ok'])) {
      if (($created['error'] ?? '') === 'too_many_feeds') {
        fail('too_many_feeds', 'フィードは1利用者あたり' . FEED_MAX_PER_USER . '本までです。', 409);
      }
      fail('storage_failed', 'フィードを発行できませんでした。', 500);
    }

    pushLog("feed_create: service={$service} userid={$userid} mode={$mode}");
    // token と view_url はこの応答にしか現れない。サーバは生トークンを
    // 保存していないため、あとから取り出すことはできない。
    respond(true, [
      'feed_id'   => (string)$created['feed']['feed_id'],
      'mode'      => $mode,
      'feed_url'  => feedSubscribeUrl((string)$created['token']),
      'view_url'  => feedViewUrlWithKey((string)$created['token'], (string)$created['key_b64']),
    ]);
  }

  case 'feed_list': {
    $service = inputStr($input, 'service');
    $userid  = inputStr($input, 'userid');
    $feeds = [];
    foreach (feedsFor($service, $userid) as $feed) {
      $feeds[] = [
        'feed_id'    => (string)($feed['feed_id'] ?? ''),
        'mode'       => (string)($feed['mode'] ?? ''),
        'created'    => (int)($feed['created'] ?? 0),
        'last_poll'  => (int)($feed['last_poll'] ?? 0),
        'poll_count' => (int)($feed['poll_count'] ?? 0),
      ];
    }
    respond(true, ['feeds' => $feeds]);
  }

  case 'feed_revoke': {
    $service = inputStr($input, 'service');
    $userid  = inputStr($input, 'userid');
    $feedId  = inputStr($input, 'feed_id');
    if ($service === '' || $userid === '' || $feedId === '') {
      fail('invalid_input', 'service・userid・feed_idは必須です。');
    }
    if (!feedRevoke($service, $userid, $feedId)) {
      fail('not_found', '対象のフィードが見つかりません。', 404);
    }
    pushLog("feed_revoke: service={$service} userid={$userid} feed_id={$feedId}");
    respond(true, []);
  }

  default:
    fail('unknown_action', '不明なアクションです。', 404);
}
