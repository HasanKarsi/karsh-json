# karsh-json

Hatanın nerede ve neden olduğunu söyleyen bir JSON ayrıştırıcı; yanına da
yapıştırılan "neredeyse JSON"u onaran, ağacı geri yazan, sır arayan ve n8n
workflow dosyalarını okuyan parçalar. Bağımlılığı yok.

*A JSON parser that says what is wrong, where and why — with repair for the
near-JSON people actually paste, a printer that changes nothing but whitespace,
a secret scanner and an n8n workflow reader beside it. No dependencies.*

---

## Türkçe

### Ne işe yarar

`JSON.parse` neyin yanlış olduğunu aslında bilir ama bir ayrıştırıcının
diliyle söyler: fazladan virgül "Expected double-quoted property name" olur ve
ondan sonraki paranteze işaret eder; tek tırnakla yazılmış bir anahtarla
tırnaksız bir anahtar aynı mesajı alır. Bu paket tam olarak `JSON.parse`'ın
kabul ettiği dili kabul eder (ona karşı fuzz'landı) ve durduğu yeri insanın
söyleyeceği gibi söyler: satır, sütun, sorunlu metin ve hâlâ açık duran parantez.

Bir de `JSON.parse`'ın attığı şeyleri saklar: sayılar ve dizeler **yazıldıkları
metin olarak** durur, üyeler belge sırasını ve yinelenenleri korur. Bu yüzden
biçimlendirme `12345678901234567890`'ı `12345678901234567000` yapmaz, `1.0`'ı
`1`'e indirmez, aynı anahtarın ikincisini silmez.

Yedi dosya, yedi iş:

| Dosya | İş |
| --- | --- |
| `parse` | Konum bildiren ayrıştırıcı; ağaç, istatistik ve yinelenen anahtarlar. |
| `repair` | JavaScript nesnesi, JSON5, Python çıktısı ya da sohbetten gelen metni JSON'a çevirir. |
| `print` | Ağacı geri yazar: girintili ya da tek satır, istenirse anahtarlar sıralı. |
| `secrets` | Bir dizenin içindeki anahtar/parola: hem bilinen biçimler hem "şüpheli isim + düz değer". |
| `n8n` | Workflow dışa aktarımını okur: düğümler, tetikleyiciler, bağlantılar, sızıntılar, temizlenmiş kopya. |
| `decode` | Açılan dosyanın baytlarını metne çevirir (UTF-8 ve iki UTF-16). |
| `check` | Hepsi tek çağrıda — arayüzün ihtiyaç duyduğu tek geçiş. |

### Kurulum

Paket derlenmiş dosya taşımaz; TypeScript kaynağı olduğu gibi yayımlanır
(`exports` doğrudan `src/index.ts`'i gösterir). Build adımı yoktur.

```bash
npm i github:HasanKarsi/karsh-json
```

Node 18 ve üzeri (`atob` ve `structuredClone` için), ya da herhangi bir
tarayıcı.

### Kullanım

**1. Hata nerede?**

```ts
import { parseJson, errorExcerpt } from "karsh-json";

const text = `{
  "ad": "KARSH",
  "sayi": 12,
}`;

const result = parseJson(text);
// { ok: false, error: { code: "trailingComma", offset: 31, line: 3, column: 13, expected: "}" } }

if (!result.ok) {
  errorExcerpt(text, result.error.offset);
  // { before: '  "sayi": 12', after: ",", clippedStart: false, clippedEnd: false }
  // `before` imlece kadar olan kısım: ok satırını yazı tipine bırakmadan çizebilirsin.
}
```

`offset`, `setSelectionRange`'in beklediği UTF-16 konumudur; `column` ise kod
noktasıyla sayılır, yani satırın başındaki bir emoji bir kolon sayılır.

**2. Yapıştırılanı onar, sonra olduğu gibi geri yaz**

```ts
import { repairJson, parseJson, printJson } from "karsh-json";

repairJson("{ad: 'KARSH', /* not */ liste: [1,2,],}");
// { text: '{"ad": "KARSH",   "liste": [1,2]}', changed: true,
//   fixes: { trailingComma: 2, comment: 1, quote: 1, unquotedKey: 2, literal: 0, invisible: 0, controlChar: 0 } }

const parsed = parseJson('{"b":1,"a":12345678901234567890,"n":1.0,"b":2}');
if (parsed.ok) {
  parsed.duplicates;
  // [{ key: "b", path: [], offset: 40, line: 1, column: 41 }] — ikisi de duruyor

  printJson(parsed.root, { indent: "  ", sortKeys: true });
  // {
  //   "a": 12345678901234567890,   <- basamaklar aynı
  //   "b": 1,
  //   "b": 2,                      <- yinelenen silinmedi
  //   "n": 1.0                     <- 1.0, "1" değil
  // }
}
```

Geçerli JSON `repairJson`'dan bayt bayt aynı çıkar (fuzz'landı); düğmeyi
göstermeyi güvenli kılan da bu. Kapanış tırnağı temiz bulunamayan bir dize
olduğu gibi bırakılır — tahmin edilmez, ayrıştırıcı ona işaret edebilsin diye.

**3. Sır ara, workflow'u oku**

```ts
import { scanString, analyseN8n, sanitise } from "karsh-json";

scanString("Bearer sk-ant-api03-...", null); // "..." anahtarın kalanı, tam metin 115 karakter
// [{ kind: "anthropic", start: 7, end: 115, masked: "sk-a••••••••" }] — biçim tanınıyorsa ad gerekmez

scanString("hunter2", "password");          // [{ kind: "named", … }] — şüpheli ad + düz değer
scanString("={{ $credentials.token }}", "password"); // [] — bu bir referans, sır değil

const report = analyseN8n(workflow);
report?.workflows[0].triggers;
// [{ node: "Webhook", kind: "webhook", type: "n8n-nodes-base.webhook", detail: "POST /orders" }]
report?.workflows[0].findings;
// [{ node: "HTTP Request", path: "parameters.headerParameters.parameters[0].value",
//    field: "Authorization", kind: "anthropic", masked: "sk-a••••••••" }]
report?.workflows[0].webhooks;
// [{ node: "Webhook", method: "POST", path: "orders", open: true }] — kimlik doğrulaması yok

sanitise(workflow, report, 2);
// "Bearer <redacted:anthropic-api-key>" — paylaşılabilir kopya: sırlar, sabitlenmiş
// çalışma verisi ve instance id çıkarılmış hâli
```

Ya da hepsi tek çağrıda:

```ts
import { check } from "karsh-json";

check(text);
// { text, result, bytes: 34, lines: 4,
//   n8n: null,                                  <- n8n dışa aktarımı değil
//   repair: { result: …, valid: true } }        <- onarım gerçekten çözüyor, düğme sözünü tutar
```

### API

| İmza | Ne döner |
| --- | --- |
| `check(text)` | Tek geçiş: ayrıştırma, bayt ve satır sayısı, n8n raporu (varsa) ve onarım önizlemesi. |
| `parseJson(text)` | `{ ok: true, root, stats, duplicates, duplicateCount }` ya da `{ ok: false, error }`. `error`: kod, `offset`, `line`, `column`, `found`, `expected` ve açık kalan parantez. |
| `locate(text, offset)` · `errorExcerpt(text, offset, width)` | Konumdan satır/sütun; ve hatanın çevresi — iki megabaytlık tek satırlık dosyada bile yalnızca çevresi okunur. |
| `formatPath(path)` · `utf8Length(text)` · `countLines(text)` | `nodes[0].parameters["odd key"]` biçiminde yol; gerçek bayt uzunluğu; satır sayısı. |
| `repairJson(input)` | `{ text, changed, fixes }` — hangi düzeltmeden kaç tane yapıldığı sayılır. |
| `printJson(root, { indent, sortKeys })` | Ağacı geri yazar. `indent`: iki boşluk, dört boşluk, sekme ya da `null` (tek satır). |
| `PRINT_LIMIT` · `OutputTooLargeError` | Çıktı tavanı: on bin iç içe dizi gigabaytlarca metne açılır, bu onu ölü sekme yerine açıklanabilir bir hataya çevirir. |
| `scanString(value, name)` | Bir dizedeki bulgular: bilinen biçimler her yerde; "şüpheli ad + düz değer" ise yalnızca gerçekten değer yazılmışsa. |
| `redact(value, hits)` · `mask(value)` · `placeholder(kind)` | Değeri yer tutucuyla değiştir; ekranda göstermek için maskele; bir tür için yer tutucu metni. |
| `nameStrength(name)` · `isSecretName(name)` · `isPlaceholder(value)` | Ad ne kadar bağlayıcı (`password`, `secret`, `weak`); bu ad bir sır adı mı; bu değer zaten yer tutucu mu. |
| `mightBeN8n(root)` · `isWorkflow(value)` | Ucuz ön eleme (ağaç üzerinde) ve kesin kontrol (nesneler üzerinde). |
| `analyseN8n(value)` | Düğümler, tetikleyiciler, bağlantılar, kopuk uçlar, yalnız düğümler, kimlik referansları, sızıntılar, sabitlenmiş veri, webhook'lar. n8n değilse `null`. |
| `sanitise(value, report, indent)` | Paylaşılabilir kopya: sırlar yer tutucuyla, sabitlenmiş çalışma verisi ve instance id çıkarılmış. |
| `decodeText(bytes)` | Baytları metne çevirir (UTF-8, UTF-16LE, UTF-16BE); ikili dosyada `null`. |
| `isEditOf(previous, next)` · `errorSlots(error)` | Yeni metin öncekinin düzenlenmiş hâli mi (imleci korumak için); ve hata mesajındaki boşlukların dolduracağı değerler. |

### Neden kütüphane değil, elle yazıldı

Çünkü istenen şey "ayrıştır" değil, "neyin yanlış olduğunu **göster**"di.
`JSON.parse` bir istisna atar ve mesajı motordan motora değişir; satır ve sütun
verse bile fazladan virgülü virgülün kendisinde değil ondan sonra gelen
karakterde gösterir. Bir editörün imleci oraya götürebilmesi için hatanın
yapılandırılmış olması gerekiyordu: kod, konum, sorunlu metin, açık parantez.

İkinci sebep sadakat. Bir biçimlendirici `JSON.parse` + `JSON.stringify`
üstüne kurulursa, büyük tam sayıları sessizce bozar, `1.0`'ı `1` yapar,
anahtarları JavaScript'in nesne sırasına sokar (tam sayı gibi duran anahtarlar
başa geçer) ve yinelenen anahtarın ilkini atar. Bu paket ölçekleri metin olarak
sakladığı için biçimlendirme **yalnızca boşluğu** değiştirir — yinelenen
anahtarı da uyarı olarak gösterebilir, çünkü hâlâ oradadır.

Üçüncüsü sınır davranışı: V8'in `JSON.parse`'ı çağrı yığınının kaldırdığından
çok daha derin iç içe geçmeyi kabul eder. "Tam olarak `JSON.parse`'ın kabul
ettiğini kabul eder" sözü orada da tutulsun diye ayrıştırıcı özyinelemesiz
yazıldı: açık bir yığınla, döngüyle.

n8n tarafı da aynı sebeple burada: bir workflow dışa aktarımında şifreler
şifreli veritabanında kalır, ama insanların parametrelere **yazdıkları** kalmaz
— başlık alanına yapıştırılan anahtar, Code düğümündeki token, bağlantı
dizesindeki parola. Bunu arayan hazır bir şey yoktu; olsa bile `{{ }}` içindeki
bir referansla düz bir parolayı ayırt etmesi gerekirdi.

### Lisans

MIT — bkz. [LICENSE](./LICENSE).

---

## English

### What it is for

`JSON.parse` knows exactly what is wrong, but it says it in a parser's terms: a
trailing comma becomes "Expected double-quoted property name", pointed at the
bracket after it, and a single-quoted key and an unquoted key get the same
message. This package accepts precisely the language `JSON.parse` accepts
(fuzzed against it) and names where it stopped the way a person would: the line
and column, the offending text, and which bracket is still open.

It also keeps what `JSON.parse` throws away: scalars stay as **the text they
were written as**, and members keep document order and duplicates. So
formatting never turns `12345678901234567890` into `12345678901234567000`, or
`1.0` into `1`, and never drops the first of two identical keys.

Seven files, seven jobs:

| File | Job |
| --- | --- |
| `parse` | The locating parser: tree, statistics, duplicate keys. |
| `repair` | Turns a JavaScript object literal, JSON5, a Python printout or a chat message into JSON. |
| `print` | Writes the tree back out: indented or on one line, keys sorted on request. |
| `secrets` | A key or password inside a string: known formats, and "suspicious name plus a literal value". |
| `n8n` | Reads a workflow export: nodes, triggers, connections, leaks, sanitised copy. |
| `decode` | The bytes of an opened file as text (UTF-8 and both UTF-16s). |
| `check` | All of it in one call — the single pass an interface needs. |

### Install

No build step and no compiled files: the package ships TypeScript source and
`exports` points straight at `src/index.ts`.

```bash
npm i github:HasanKarsi/karsh-json
```

Node 18 or newer (for `atob` and `structuredClone`), or any browser.

### Usage

**1. Where is the error?**

```ts
import { parseJson, errorExcerpt } from "karsh-json";

const text = `{
  "ad": "KARSH",
  "sayi": 12,
}`;

const result = parseJson(text);
// { ok: false, error: { code: "trailingComma", offset: 31, line: 3, column: 13, expected: "}" } }

if (!result.ok) {
  errorExcerpt(text, result.error.offset);
  // { before: '  "sayi": 12', after: ",", clippedStart: false, clippedEnd: false }
  // `before` ends just before the offending character, so the caret row can be drawn from it.
}
```

`offset` is the UTF-16 offset `setSelectionRange` takes; `column` counts code
points, so an emoji earlier on the line counts once.

**2. Repair what was pasted, then write it back unchanged**

```ts
import { repairJson, parseJson, printJson } from "karsh-json";

repairJson("{ad: 'KARSH', /* note */ liste: [1,2,],}");
// { text: '{"ad": "KARSH",   "liste": [1,2]}', changed: true,
//   fixes: { trailingComma: 2, comment: 1, quote: 1, unquotedKey: 2, literal: 0, invisible: 0, controlChar: 0 } }

const parsed = parseJson('{"b":1,"a":12345678901234567890,"n":1.0,"b":2}');
if (parsed.ok) {
  parsed.duplicates;
  // [{ key: "b", path: [], offset: 40, line: 1, column: 41 }] — both are still there

  printJson(parsed.root, { indent: "  ", sortKeys: true });
  // {
  //   "a": 12345678901234567890,   <- every digit kept
  //   "b": 1,
  //   "b": 2,                      <- the duplicate is not dropped
  //   "n": 1.0                     <- 1.0, not 1
  // }
}
```

Valid JSON comes out of `repairJson` byte for byte (fuzzed), which is what
makes it safe to offer the button at all. A string whose closing quote cannot
be found cleanly is left exactly as it was — nothing is guessed, so the parser
can point at it.

**3. Look for secrets, read the workflow**

```ts
import { scanString, analyseN8n, sanitise } from "karsh-json";

scanString("Bearer sk-ant-api03-...", null); // "..." stands for the rest of the key; 115 characters in all
// [{ kind: "anthropic", start: 7, end: 115, masked: "sk-a••••••••" }] — a known format needs no name

scanString("hunter2", "password");                   // [{ kind: "named", … }] — name plus a literal
scanString("={{ $credentials.token }}", "password"); // [] — a reference, not a secret

const report = analyseN8n(workflow);
report?.workflows[0].triggers;
// [{ node: "Webhook", kind: "webhook", type: "n8n-nodes-base.webhook", detail: "POST /orders" }]
report?.workflows[0].findings;
// [{ node: "HTTP Request", path: "parameters.headerParameters.parameters[0].value",
//    field: "Authorization", kind: "anthropic", masked: "sk-a••••••••" }]
report?.workflows[0].webhooks;
// [{ node: "Webhook", method: "POST", path: "orders", open: true }] — takes calls with no auth

sanitise(workflow, report, 2);
// "Bearer <redacted:anthropic-api-key>" — the shareable copy, with secrets, pinned
// execution data and the instance id removed
```

Or all of it at once:

```ts
import { check } from "karsh-json";

check(text);
// { text, result, bytes: 34, lines: 4,
//   n8n: null,                           <- not an n8n export
//   repair: { result: …, valid: true } } <- the repair really does parse, so the button can promise it
```

### API

| Signature | Returns |
| --- | --- |
| `check(text)` | One pass: the parse, bytes and lines, the n8n report when there is one, and a repair preview. |
| `parseJson(text)` | `{ ok: true, root, stats, duplicates, duplicateCount }` or `{ ok: false, error }`. The error carries a code, `offset`, `line`, `column`, `found`, `expected` and the bracket still open. |
| `locate(text, offset)` · `errorExcerpt(text, offset, width)` | Line and column from an offset; and the neighbourhood of the error — only the neighbourhood is read, even in a two-megabyte single line. |
| `formatPath(path)` · `utf8Length(text)` · `countLines(text)` | A path as `nodes[0].parameters["odd key"]`; the real byte length; the line count. |
| `repairJson(input)` | `{ text, changed, fixes }`, with each kind of fix counted. |
| `printJson(root, { indent, sortKeys })` | Writes the tree back out. `indent`: two spaces, four spaces, a tab, or `null` for one line. |
| `PRINT_LIMIT` · `OutputTooLargeError` | A ceiling on the output: ten thousand nested arrays format to gigabytes, and this turns that into an error an interface can explain instead of a dead tab. |
| `scanString(value, name)` | Findings in one string: a known format anywhere, a "suspicious name plus a literal" only when a value was really typed. |
| `redact(value, hits)` · `mask(value)` · `placeholder(kind)` | Replace a value with a placeholder; mask it for display; the placeholder text for a kind. |
| `nameStrength(name)` · `isSecretName(name)` · `isPlaceholder(value)` | How binding the name is (`password`, `secret`, `weak`); whether it is a secret's name at all; whether the value is already a placeholder. |
| `mightBeN8n(root)` · `isWorkflow(value)` | The cheap look (over the tree) and the real check (over objects). |
| `analyseN8n(value)` | Nodes, triggers, connections, dangling edges, isolated nodes, credential references, leaks, pinned data, webhooks. `null` when it is not n8n. |
| `sanitise(value, report, indent)` | The shareable copy: secrets replaced, pinned execution data and the instance id removed. |
| `decodeText(bytes)` | Bytes as text (UTF-8, UTF-16LE, UTF-16BE); `null` for binary data. |
| `isEditOf(previous, next)` · `errorSlots(error)` | Whether the new text reads as an edit of the old one (so a cursor can be kept); and the values a message's slots are filled with. |

### Why this is written out rather than pulled in

Because what was needed was not "parse it" but "**show** what is wrong".
`JSON.parse` throws, its message differs between engines, and even where it
gives a line and column it points at the character after the trailing comma
rather than at the comma. For an editor to move the caret there, the error had
to be structured: a code, a position, the offending text, the open bracket.

The second reason is fidelity. A formatter built on `JSON.parse` plus
`JSON.stringify` quietly breaks large integers, turns `1.0` into `1`, reorders
keys into JavaScript's object order (integer-like keys hoisted to the front)
and drops the first of two identical keys. Here scalars are kept as text, so
formatting changes **whitespace only** — and duplicates can be reported as a
warning, because they are still there.

The third is the edges: V8's `JSON.parse` accepts nesting far deeper than the
call stack allows. For "accepts exactly what `JSON.parse` accepts" to hold
there too, the parser is iterative — an explicit stack, no recursion.

The n8n part is here for the same reason. In a workflow export the credentials
themselves stay encrypted in n8n's database, but what people **type into
parameters** does not: the key pasted into a header field, the token in a Code
node, the password in a connection string. Nothing off the shelf looked for
that, and anything that did would still have to tell a reference inside
`{{ }}` apart from a password typed in plain.

### License

MIT — see [LICENSE](./LICENSE).
