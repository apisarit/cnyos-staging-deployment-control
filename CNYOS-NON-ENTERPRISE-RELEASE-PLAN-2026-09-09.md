# CNYOS — แผนปล่อยระบบโดยไม่พึ่ง GitHub Enterprise

วันที่: 2026-09-09 · สถานะ: **ข้อเสนอเพื่อรับการตรวจอิสระ ยังไม่อนุมัติให้ใช้งานจริง**

## สรุปสำหรับเจ้าของระบบ

ผู้ใช้อนุญาตให้จัดทำแผนทางเลือก และยืนยันให้ดำเนินการต่อแล้ว ไม่ต้องขออนุญาตจัดทำแผนซ้ำ
การอนุญาตครั้งนี้ไม่ใช่ security sign-off, การยอมรับความเสี่ยงของฐานข้อมูล หรือคำอนุมัติ deploy รุ่นใดรุ่นหนึ่ง

ข้อเสนอคือ **ผู้รับผิดชอบเป็นผู้เริ่มการปล่อยระบบ แต่ระบบควบคุมแยกเป็นผู้ตรวจและดำเนินการ**
แทนการอาศัย required reviewers ของ GitHub Environment ใน private repository
การตรวจสิทธิ์ รุ่นไฟล์ เป้าหมาย และการกู้คืนยังต้องบังคับใช้จริง ไม่ใช่เพียงรายการให้คนติ๊กว่าเสร็จ

- เก็บ repository ใหม่เป็น private และยังไม่ใส่ secrets หรือเปิด workflows
- เก็บ PR #36 เป็น draft ไม่ merge เพื่อทำ staging และไม่ให้ AI ลงนามแทนผู้ตรวจ
- เริ่มพิสูจน์วิธีใหม่ด้วยข้อมูลจำลองในสภาพแวดล้อมแยกเท่านั้น หลังผ่านการอนุมัติแต่ละขั้น
- แยกการทดสอบ staging, การ deploy Production และการอนุญาตใช้ข้อมูลคนไข้จริงออกจากกัน
- ไม่ซื้อ GitHub Enterprise ไม่เปลี่ยน repo เป็น public และไม่เลือกบริการที่มีค่าใช้จ่ายแทนผู้ใช้

**ข้อจำกัดสำคัญ:** วิธีนี้ยังไม่มีระบบรองรับที่พิสูจน์แล้ว จึงยังระบุวันเสร็จหรือเปอร์เซ็นต์พร้อม Production ไม่ได้
การไม่ซื้อ Enterprise ไม่ได้แปลว่าไม่มีค่าใช้จ่ายด้านเครื่องรัน ระบบสิทธิ์ ที่เก็บหลักฐาน หรือผู้ตรวจ
ต้องผ่านการตรวจความเป็นไปได้ก่อนลงทุนเขียนระบบทดแทนเพิ่มเติม

## 1. ขอบเขตและหลักฐานตั้งต้น

เอกสารนี้เป็นงานออกแบบในเครื่องเท่านั้น ไม่แก้ไฟล์นโยบายหรือ executable guards ในแอป
ไม่มีคำสั่ง deploy, SQL ที่เปิดใช้งาน, credentials, ลายเซ็นจำลอง หรือหลักฐานผ่าน gate ที่สร้างขึ้นเอง

Source inspected: `work/controller-boundary-hardening`, branch
`agent/controller-boundary-hardening`, local HEAD
`4e98152f91c65bb7089222145b04620ba919306a`, **dirty checkout**.
ผลทดสอบงานที่ยังไม่ commit ต้องไม่อ้างว่าเป็นผลของ HEAD นี้หรือ remote PR

หลักฐานล่าสุดที่เก็บไว้ใน checkpoint ระบุว่า private controller repository ถูกสร้างแล้ว
และ GitHub แจ้งว่า branch protection ยังไม่บังคับใช้กับบัญชี/repo นั้น
นี่ไม่ใช่หลักฐานว่า public application repository ไม่มี branch protection
การตรวจสดครั้งถัดไปต้องตรวจแต่ละ repository และแต่ละ environment แยกกัน

เอกสาร GitHub ระบุว่าความสามารถของ protected branches แตกต่างตามแผนและ visibility
และ required Environment reviewers ของ Free/Pro/Team ใช้ได้เฉพาะ public repositories
ดังนั้นอัปเกรด Pro/Team เพียงอย่างเดียวไม่ตอบข้อกำหนด private controller เดิม
([Protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches),
[Environment reviewers](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#required-reviewers))

Netlify รองรับ manual deploy โดยไม่ผ่าน continuous deployment แต่ความสามารถนี้ไม่ได้รับรอง
การแยก credentials หรือการอนุมัติของ CNYOS ให้โดยอัตโนมัติ
([Netlify deploy methods](https://docs.netlify.com/deploy/create-deploys/#netlify-cli))

## 2. การตัดสินใจด้านสถาปัตยกรรมที่เสนอ

### 2.1 GitHub เป็นแหล่ง source ไม่ใช่ผู้อนุมัติให้ปล่อยระบบ

เก็บ source และประวัติ review ใน GitHub ได้ แต่ private controller branch ที่ไม่มีการบังคับ protection
ต้องไม่เป็น trust root ที่ทำให้โค้ดได้รับ secrets อัตโนมัติ

เสนอให้ executor ที่มีผู้ดูแลแยกจากผู้พัฒนา รับเฉพาะชุด controller ที่ตรวจแล้วแบบ immutable
ซึ่งรวม scripts, policy, dependency lock, runtime image/config และ public-key registry ไว้ใน digest เดียว
ผู้ตรวจและเจ้าของความเสี่ยงถือ signing keys คนละชุด และอนุมัติทั้งชุด controller กับงาน release อย่างแยกชัดเจน
การเปลี่ยน registry, runtime, policy หรือ controller ต้องผ่าน review ใหม่ รวมถึงการเพิกถอน key และป้องกัน downgrade
เก็บประวัติการยอมรับ controller ในที่เก็บที่ผู้เริ่ม release เขียนทับย้อนหลังไม่ได้

executor ต้องตรวจชุดที่ได้รับอนุญาตก่อนอ่าน deployment secrets ไม่ใช้ branch ล่าสุดจาก GitHub มาแทน digest ที่อนุมัติ
ต้องไม่มีการเปิด interactive shell, ดาวน์โหลดโค้ดเพิ่มเติม หรือติดตั้ง dependency ระหว่างถือ deployment credentials
การดูแลเครื่อง ระบบ identity และที่เก็บหลักฐานต้องไม่มีช่องทางให้ผู้พัฒนา/ผู้เริ่ม release เปลี่ยนตัวตรวจของตนเอง
รูปแบบการบังคับใช้และขอบเขตอำนาจ administrator ต้องมีหลักฐาน ไม่รับเพียงคำรับรองว่าเครื่องปลอดภัย

การตรวจต้องครอบคลุม base OS/runtime, launcher, verifier และช่องทางปล่อย credentials ไม่ใช่เฉพาะ controller bundle
ผู้ดูแลต้องเสนอ independently verified measurement ของ trusted computing base (TCB), ตารางอำนาจ/การสมรู้ร่วมคิด
และกระบวนการ upgrade, rollback, break-glass ที่ผู้เริ่มงานทำคนเดียวไม่ได้
credential authority ต้องยอมรับเฉพาะ executor measurement และ release-root digest ที่ตรวจแล้ว
พร้อมอำนาจอายุสั้นที่ผูกกับงานนั้น; self-attestation จาก executor ไม่เพียงพอ

### 2.2 Human-initiated ไม่ใช่ manual bypass

ผู้รับผิดชอบเริ่มงานและยืนยันตัวตนกับระบบ release ที่แยกต่างหาก
ระบบนั้นออก challenge และ session identity ของตนเอง ไม่คัดลอก `GITHUB_*` หรือ `ACTIONS_ID_TOKEN_REQUEST_*`
ลงเครื่องเพื่อหลอกให้ runtime เดิมผ่าน

authorization รูปแบบใหม่ต้องมี version/domain แยกจาก GitHub Actions packet เดิม และผูกอย่างน้อยกับ:

- controller digest, policy/registry version และ executor identity;
- release/session ID, attempt, nonce แบบใช้ครั้งเดียว, issuer, audience, เวลาออกและหมดอายุ;
- ตัวตนผู้ตรวจอิสระและเจ้าของความเสี่ยงที่ต่างกัน พร้อมสถานะ key/session ที่ยังไม่ถูกเพิกถอน;
- source commit/tree, manifests, static bytes, Function inputs/bundles และ dependency/runtime digests;
- staging site/database identities, known-good rollback และรุ่นของ durable recovery policy;
- reference และ digest ของ exact-source security decision และ separate migration-promotion decision.

ผูก database system identifier, exact pre/post ledger/schema/baseline evidence จากขั้น C,
ordered-migration digest และคำตัดสิน app↔schema compatibility/recovery ไว้ด้วยก่อน app promotion
หากฐานข้อมูลเปลี่ยนหลัง evidence ให้หยุดและประเมินใหม่ ไม่คืนแอปรุ่นเก่าที่ใช้กับ schema ปัจจุบันไม่ได้
การเปลี่ยนฐานข้อมูลต้องมี authorization ของตนเอง ไม่ได้อำนาจจาก app release packet

คงขอบเขตเดิมไว้เป็นฐาน: authorization ไม่เกิน 30 นาที, nonce อย่างน้อย 32 bytes และ attempt ที่อนุมัติชัดเจน
การยืดอายุหรือเปลี่ยน retry/attempt semantics ต้องผ่าน review ไม่ใช่ผลข้างเคียงของ identity adapter

proposal นี้ไม่สร้าง packet หรือ key จริง ยังไม่ตัดสินใจเลือก identity provider
การอนุมัติในแชต ภาพหน้าจอ dashboard หรือ actor string ไม่ใช่ authenticated release identity
ผู้ตรวจต้องระบุวิธีตรวจ signature, expiry, replay และ revocation ที่บังคับใช้ได้จริง

เพิ่มเป็น design acceptance ว่า signers ใช้ phishing-resistant proof-of-possession และ keys ที่ export ไม่ได้
พร้อม recent re-authentication ทั้งสองคนต้องสร้าง/ตรวจ canonical challenge และดู exact controller/release fields
จากแหล่งที่เชื่อถือได้ของตนเอง ไม่เชื่อภาพ digest ที่ operator แสดงเพียงฝ่ายเดียว
ประวัติที่มีผู้ตรวจอิสระยืนยันต้องตรวจความสอดคล้องได้ เพื่อปฏิเสธกรณีส่งคนละ capsule ให้ผู้ลงนามสองคน

### 2.3 แยก build, publish, ตรวจ runtime และ recovery

candidate code เป็นข้อมูลที่ยังไม่เชื่อถือ ใช้เฉพาะ Git objects ของ commit/tree ที่กำหนด
การ hermetic static/Function rebuild ต้องแยกเครื่อง/สภาพแวดล้อม ไม่มี secrets ปิดเครือข่ายระหว่าง build
และไม่รับ overlay จาก dirty worktree โดยคง static policy `networkDisabledDuringBuild: true`
การจัดหา dependency/toolchain ที่อนุมัติทำในขั้นก่อน build แยกต่างหากแบบไม่มี credentials
และส่งเข้า builder เฉพาะ immutable inputs ที่ตรวจ integrity แล้ว
protected component แต่ละ phase ใช้เฉพาะ controller ที่ตรวจแล้ว พร้อมไฟล์ผลลัพธ์ที่ตรวจ hash/ขนาด/ชนิด/path ซ้ำ
general-purpose provider publish token อยู่กับ mutation authority ในข้อ 2.4 เท่านั้น ไม่ส่งให้ operator/executor
credentials อื่น เช่น draft-access หรือ database UAT อยู่เฉพาะ protected component ของ phase นั้น

manifest ต้องผูก SHA-256 ของ canonical bounded object inventory/pack และ Git modes ไม่ใช่ commit/tree ชื่ออย่างเดียว
ปฏิเสธ gitlinks/submodules, LFS/filter transformations, symlinks/nonregular entries, sparse omissions,
duplicate/case-normalization/file-directory collisions และจำนวน/ขนาดรวมที่เกินขอบเขต

แยก lifetime ของงานที่ใช้ identity/broker, publish token, private-draft access, database UAT และ rollback token
ห้ามเปลี่ยน credential class ใน runner เดิมหลังเคยได้รับอีก class หนึ่ง
ส่งต่อเฉพาะหลักฐานที่จำกัดรูปแบบและผูก hash ไม่ส่งต่อ raw tokens

คงข้อจำกัด Function evidence ว่าเป็น deployment-process provenance:
`functionByteAttestationAvailable: false` จนกว่าจะมีวิธีตรวจ remote bytes ที่พิสูจน์ได้จริง
ไม่เปลี่ยนถ้อยคำนี้ให้ดูเหมือน cryptographic remote-byte attestation

### 2.4 การสั่ง publish ต้องบังคับสิทธิ์และกู้คืนได้

ต้องมี service ที่ดูแลแยกสำหรับ durable intent, single-use admission, publisher exclusion และ recovery
ทุก mutation ต้องมี run/nonce/artifact/site/fencing-generation ที่ตรงกันก่อนเริ่ม
ต้องปฏิเสธ Git/UI/hooks/tokens/workflows อื่นที่เข้าถึง staging เดียวกันได้อย่างบังคับใช้จริง
hard-coded site ID, process lock ใน laptop หรือ Publisher role เพียงอย่างเดียวไม่พิสูจน์ขอบเขตอำนาจ token

กลไกที่เสนอให้เลือกตรวจคือ **mutation authority ที่ป้องกันแยก ถือ provider publish credential และทำ exact write เอง**
ไม่ส่ง general-purpose Netlify token ให้ operator/executor พร้อม receipt ที่อ้างว่าใช้ได้ครั้งเดียว
เพราะ token นั้นยังใช้ข้าม admission ได้ ต้องกำหนดจุดที่ admission ถูกใช้ไป (linearization point),
stable idempotency key/ownership marker, การเพิกถอนก่อน write และวิธีตรวจผลที่ provider อาจทำสำเร็จแล้วแต่ตอบกลับไม่ถึง
หากเสนอ provider-issued single-use capability แทน ต้องมีเอกสารและการพิสูจน์การผูก site/deploy/run/generation จริง
ไม่สมมติว่า Netlify มีความสามารถนี้แล้ว กลไก custody ใหม่นี้ต้อง review และเปลี่ยน caller/receipt contracts ร่วมกัน

เก็บ authorization และ raw signed recovery inputs ใน immutable restricted store ก่อนอ่าน publish credential
และบันทึก draft intent ก่อน Netlify mutation แรก
มี watchdog ที่ทำงานต่อได้เมื่อผู้ปฏิบัติงานออฟไลน์ เครื่องดับ หรือคำตอบจาก provider สูญหาย
ใช้ rollback identity คนละตัวกับ publisher และจำกัด staging เท่านั้น

การ release lease ต้องยังเหลือ barrier จนกว่าจะเก็บหลักฐานปลายทางครบ
TTL, timeout หรือการกด retry ไม่ทำให้ barrier หายหรืออนุมัติ publish ใหม่
recovery ต้องตรวจ current deploy และ run ownership ก่อนคืน known-good หรือจัดการ draft
ห้ามย้อนทับ deploy ของงานอื่น และต้องแยก terminal success ออกจากงานที่ยังต้อง rollback

durable store และ registry ต้องต้านการ restore snapshot เก่า, stale replica และ split-brain
โดยมี monotonic generation/checkpoint ที่ตรวจยืนยันแยกได้ ไม่เชื่อ append-only flag ในฐานข้อมูลเดียวอย่างเดียว
ต้องกำหนด trusted-time/clock-skew semantics เพื่อไม่ให้การย้อนนาฬิกาคืนชีพ nonce/key/session ที่หมดอายุ
ถ้ายืนยันความสดหรือความสอดคล้องไม่ได้ ให้คง barrier และหยุด mutation

**Feasibility blocker:** การอ่านสถานะ GitHub สดแล้วส่งคำสั่ง Netlify ต่อกัน ไม่ใช่ atomic transaction ข้ามสองบริการ
ผู้ตรวจต้องยอมรับ protocol ที่พิสูจน์ fresh-state admission, revocation/fencing และ exact mutation ตามข้อกำหนดเดิม
พร้อมทดสอบช่องว่างระหว่างการอ่านกับการเขียน ห้ามเรียก cached observation หรือการดูหน้า PR ด้วยคนว่าแก้ปัญหานี้แล้ว
หากบริการที่เลือกทำไม่ได้ ให้หยุดที่ design gate และนำข้อจำกัดกลับมาทบทวน ไม่ถอดเงื่อนไขเงียบ ๆ

Netlify deploy lock หยุด auto-publishing แต่ยังสร้าง build ได้ จึงเป็นเพียงมาตรการเสริม ไม่ใช่หลักฐานว่าไม่มี publisher อื่น
และการ rollback แอปไม่ใช่ rollback ฐานข้อมูล
([Netlify deployment management](https://docs.netlify.com/deploy/manage-deploys/manage-deploys-overview/#locked-deploys))

## 3. ตารางคงข้อกำหนดเดิมและกลไกที่จะทดแทน

| ข้อกำหนด | กลไกใหม่ที่ต้องพิสูจน์ | สถานะปัจจุบัน |
| --- | --- | --- |
| controller เปลี่ยนตัวตรวจ/ผู้อนุมัติเองไม่ได้ | immutable signed controller bundle + independently protected executor/registry/history | ยังไม่มีระบบที่เลือกและตรวจรับ |
| ผู้ตรวจอิสระและผู้รับความเสี่ยงยืนยัน exact release | authenticated sessions + distinct keys + exact-packet signatures + no self-approval/replay | ยังไม่ได้ระบุบุคคล/key custody |
| GitHub/OIDC identity ตรงกับทุก receipt | versioned non-GitHub identity adapter และ broker/consumer migration ทั้งสาย | ยังไม่ได้ implement; ห้าม spoof env |
| candidate ไม่เข้าถึง credentials | hermetic producer และแยก credential lifetimes/egress | ต้องพิสูจน์บน infrastructure จริง |
| publish เฉพาะ staging ที่อนุมัติ | fixed target authority + alternate-publisher exclusion + fresh single-use admission | ยังไม่พิสูจน์ provider enforcement |
| draft เป็น private และ cleanup ตรวจ ownership | isolated draft boundary + durable intents + independent reconciliation | service/pins ยังไม่พร้อม |
| rollback แม้ operator/runner หาย | immutable pre-mutation deposit + separate principal + independent watchdog + durable barrier | ยังไม่ผ่าน live recovery drill |
| source และไฟล์ที่ deploy ตรงกับที่ตรวจ | exact Git objects + deterministic rebuild + hash checks ทุกจุดส่งต่อ | มีงาน local บางส่วน ไม่ใช่ live proof |
| ฐานข้อมูลปลอดภัยและ ledger ถูกต้อง | ลำดับ PR36/Chananya/Jitarsa/migration เดิม ไม่ใช่การทดแทนด้วย manual release | gates เดิมยังมีผล |
| Production และข้อมูลคนไข้ต้องอนุมัติแยก | exact-commit production attestation + post-deploy admission | ไม่อยู่ในอำนาจอนุมัติแผนนี้ |

## 4. ลำดับดำเนินการพร้อมเกณฑ์จบ

### A — ตรวจความเป็นไปได้และอนุมัติ design

Owner ระบุผู้ตรวจ security อิสระ, risk owner/operator และผู้ดูแล executor/recovery
ไม่กำหนดว่า Jaoball ได้รับหน้าที่หรืออนุมัติแล้วเพียงเพราะมีชื่อในประวัติ PR

ผู้ดูแลเสนอ infrastructure ที่มีอยู่หรือทางเลือกพร้อมราคาและขอบเขตสิทธิ์ ครอบคลุม executor,
identity, immutable evidence store, publisher admission และ watchdog
ห้ามใช้ NAS ที่ได้รับอนุญาตเป็นที่สำรองข้อมูลไปเป็น executor, credential store หรือ trust root โดยอัตโนมัติ

**จบขั้นนี้เมื่อ:** ผู้ตรวจยืนยัน control equivalence ที่ทดสอบได้, owner ยอมรับขอบเขต/ผู้รับผิดชอบ/ค่าใช้จ่าย,
และมีรายการ controls ที่ยังพิสูจน์ไม่ได้เป็น blockers ชัดเจน
ถ้าไม่มี infrastructure ที่ทำได้จริง ไม่ควรเริ่ม port controller ทั้งชุดเพื่อให้ได้เพียงไฟล์ที่ยังเปิดใช้ไม่ได้

### B — พัฒนาและตรวจด้วย fixture แบบแยก

หลังอนุมัติ design/implementation จึงสร้าง immutable executor package และ identity adapter ใหม่
port เฉพาะ logic ที่ผ่าน review พร้อม update schema/consumers ทั้งสาย ใช้ domain/version ใหม่
templates ของ GitHub เดิมคง dormant; ไม่เปลี่ยน stop constants ให้ผ่านโดยไม่มี replacement

ทำ native Function build, authenticated-UAT implementation, external-service contracts และ failure/recovery tests ให้ครบ
dependency/runtime/image/key pins ต้องเป็นค่าจริงที่ผ่าน review ไม่เติมค่าจำลองเพื่อให้ activation ผ่าน
CLI รุ่นเก่าที่เคยถูกถอดจาก lock ไม่กลับมาใช้เพียงเพราะเป็น manual release

**จบขั้นนี้เมื่อ:** clean exact controller commit/digest, locked toolchain, required offline/native tests,
identity/proof consumers และ independent source review ตรงกัน พร้อม infrastructure acceptance จากขั้น A
passing fixture tests ไม่ใช่ live staging approval

### C — ลำดับฐานข้อมูล staging เดิม ไม่เปลี่ยน

1. คง PR #36 draft; independent source review ต้องตรวจ trigger/browser-RPC ACL revocation,
   enforced read-only verification และ atomic failure/rollback ของ exact source
2. exact-head CI ตามด้วย fresh exact-head read-only observation และ matching verifier จาก branch โดยไม่ merge
   drift หรือ target ที่ยังไม่ได้ยืนยันต้องหยุดและกลับไป review
3. hosted rollback-only rehearsals, managed-platform exception acceptance และ ledger enabling changes
   ต้องมีหลักฐานและอำนาจแยกตาม maintenance protocol; SQL ที่ยังมี unconditional blocker ห้ามรัน
4. Reconcile Chananya ก่อน แล้ว Jitarsa อย่างอิสระเมื่อได้รับอำนาจและยืนยัน baseline ของแต่ละ tenant
5. สร้าง separate ordered-migration PR สำหรับ candidates ที่อนุมัติ ไม่คัดลอก psql wrapper ลง migration chain
6. Apply chain เฉพาะ staging หลังอนุมัติ และเก็บ migration failure/recovery/regression evidence

security acceptance ของ source ไม่เท่ากับอนุญาต merge PR หรืออนุญาต live mutation
ก่อนใช้งานต้องชี้ชัดว่าเก็บ exact-source security decision อย่างไรโดยไม่ขัดกับ live gate ที่คง PR #36 draft/unmerged/unapproved
ไม่แก้ gate หรือใส่ GitHub approval แทนผู้ตรวจเพื่อแก้ความกำกวมนี้

### D — Controlled staging release และ acceptance

เมื่อ B/C และ live prerequisites ผ่าน จึงขออนุมัติ packet สำหรับ staging release ครั้งนั้น
เริ่มด้วย exact private draft; ตรวจ bytes/metadata/runtime/target ก่อน promote deploy ID เดิม
recovery ต้องพร้อมก่อน mutation ไม่ใช่ค่อยทำหลัง deploy ล้มเหลว

ทดสอบ synthetic accounts ทุก role, cross-tenant denials สองทิศทาง, session lifecycle,
clinical-to-payment journeys, audit/segregation และ reversible Owner OFF/ON ตาม runbook
คง scheduled backup/Owner/LINE capability restrictions จนกว่าจะผ่าน authorization ของแต่ละ capability
LINE, backup/isolated restore และ provider-level recovery ไม่ได้รับการรับรองจากการทดสอบหน้าเว็บ

**จบขั้นนี้เมื่อ:** exact artifact/deploy มีหลักฐานผ่านที่ผู้ตรวจรับรอง และทดสอบ recovery หลัง interruption ได้จริง
ยังไม่ถือว่าผ่าน Production หรือเปิดใช้คนไข้จริง

### E — Production change และ real-data admission แยกกัน

ทบทวน Production publishers, required CI/review, branch/environment protection และ credential separation แยกจาก staging
การที่ application `main` auto-publishes ยังเป็นประเด็นต้องควบคุมก่อน production release
การปิด/เปลี่ยน production auto-publishing หรือ secrets ต้องมีแผนและอำนาจเฉพาะ ไม่ทำในขั้นออกแบบ staging นี้
ข้อจำกัด private controller repo ไม่ใช่เหตุให้อนุมานว่า public application repo ไม่มี protection

ยึดทุก required gate ใน `release-readiness.json` รวม backup/restore, monitoring/incident response,
privacy/legal, clinical governance, commercial operations และ independent Quality segregation
แผนทางเลือกนี้ไม่ลด gate ให้เหลือเพียง deploy สำเร็จหรือ login ได้

หลัง exact-commit external production approval จึง deploy และตรวจ post-deploy attestation
ก่อนอนุญาตข้อมูลคนไข้จริง หากเปลี่ยนกลไก production approval ต้องมี design/review แยกและไม่แก้ readiness เพื่ออนุมัติ commit ของตนเอง
เก็บข้อกำหนด deferred ไว้: printable consent/hard copy และผู้จัดทำที่ยืนยันตัวตน/วิชาชีพได้
การเลื่อน implementation ของ feature ไม่ได้ลบหน้าที่ตรวจความพร้อมทางคลินิก

## 5. Acceptance tests ที่ต้องส่งให้ผู้ตรวจ

รายการต่อไปนี้เป็น test plan ไม่ใช่ผลทดสอบที่ผ่านแล้ว

1. เปลี่ยน controller/policy/key registry/dependency/image แม้หนึ่ง byte, downgrade root หรือเปลี่ยน base OS/launcher/verifier/secret-release path: ไม่อ่าน secret และไม่เขียน provider
2. signer ซ้ำ, key ถูกเพิกถอน, actor/env ปลอม, session ถูกขโมย/หมดอายุ, misleading digest display, split-view capsules หรือ packet replay: ปฏิเสธทั้งสาย
3. source HEAD เคลื่อน, dirty overlay, Git replacement/alternate, object-pack digest/mode/size ผิด, gitlinks/LFS/filters/symlinks/sparse omissions/path collisions หรือ overflow: ไม่เปลี่ยน bytes ที่อนุมัติหรือหยุดอย่างปลอดภัย
4. hermetic static/Function build ไม่มี credentials และ network ถูกปิดจริง; dependency acquisition แยกก่อน build
   พร้อม immutable verified inputs และไม่มี credential class ปะปนใน runner lifetime
5. site/database/tenant/Production denylist/known-good/deploy ID ต่างจาก packet: ไม่มี mutation
6. Git/UI/hook/token/manual publisher อื่นพยายามแตะ staging: ถูกปฏิเสธด้วย control plane จริง
7. GitHub read ล้มเหลว, state เปลี่ยน/ถูกเพิกถอนหลังออก admission, write ถูกหน่วง, มีการใช้ token ข้าม authority, admission replay หรือ generation ขัดแย้ง: ไม่มี promotion ที่ไม่ได้รับอนุมัติ
8. response/receipt ผิด key, origin, operation, nonce, digest หรือเวลา: ไม่ยอมรับ ไม่ส่งต่อ credential และไม่ปล่อย barrier
9. private draft เข้าได้โดยผู้ไม่มีสิทธิ์ หรือ boundary ส่ง credential ต่อให้ candidate: ถือว่าล้มเหลวและเข้ากระบวนการ recovery
10. หยุด runner/operator ในทุก transition รวม provider ทำสำเร็จแต่ response สูญหาย: reconcile ได้โดยไม่สร้างซ้ำหรือย้อนทับงานอื่น
11. terminal success/recovery แข่งกัน, callbacks ซ้ำ/ผิดลำดับ, store snapshot ถูกย้อน, split-brain/stale replica หรือนาฬิกาย้อน/เดินหน้า: มี terminal decision เดียว ไม่คืนชีพ authorization และ lease/barrier ไม่เปิดก่อนหลักฐานครบ
12. watchdog ทำงานได้เมื่อ laptop ปิด; known-good ถูกลบ/เปลี่ยนหรือไม่เข้ากับ DB ต้องหยุดก่อน mutation
    ทดสอบ migration สำเร็จแต่ app promotion ล้มเหลว: ไม่มีการคืนแอปที่ไม่เข้ากับ schema และต้องมี recovery path ที่อนุมัติแยกก่อนเริ่ม
13. ตรวจหลักฐานย้อนหลังจาก restricted store ได้ครบ source→approval→artifact→deploy→UAT/recovery โดยไม่มี tokens/PHI
14. native builder/UAT และ staging database sequence ผ่านตาม runbooks จริง; mock transports และไฟล์ receipt ว่างไม่ผ่าน

## 6. Source impact inventory สำหรับผู้ตรวจ

ทุก path ในตารางอยู่ใต้ `work/controller-boundary-hardening/` และอ้างอิง dirty source ที่ตรวจในวันที่ข้างต้น
ตารางนี้ไม่ใช่คำอนุมัติให้แก้ไฟล์เหล่านี้

| Source anchor | วิธีจัดการในข้อเสนอ |
| --- | --- |
| `ops/cnyos-staging-controller/workflow/cnyos-staging-controller.template.yml:42` และ `workflow/cnyos-staging-rollback-watchdog.template.yml:34,98` ภายใต้ controller | คง unconditional bootstrap stops; alternative ต้องมี activation acceptance ของตัวเอง |
| `ops/cnyos-staging-controller/scripts/policy.mjs:336`, `scripts/verify-authorization.mjs:772` ภายใต้ controller | เปลี่ยนเฉพาะกลไก GitHub runtime/identity ผ่าน reviewed versioned adapter ไม่ spoof environment |
| `ops/cnyos-staging-controller/scripts/reconcile-netlify-release-state.mjs:774` | migrate issuer/audience/request/receipt binding และ consumers ร่วมกัน; คง signature/freshness/operation controls |
| `supabase/manual/202609080900_close_complete_public_routine_acl_candidate.sql:46` | ห้า database blockers ต้องมี review/evidence ของฐานข้อมูลเอง ไม่เกี่ยวกับการเลือก GitHub plan |
| `scripts/generate-migration-ledger-repair-sql.mjs:21` | คง independent-review/authorization exception ทั้ง guard และ mutation block |
| `ops/cnyos-staging-controller/scripts/controller-function-bundle.mjs:722` และ `scripts/controller-authenticated-uat.mjs:122` ภายใต้ controller | ต้องมี native implementations จริงก่อน enabling change ไม่ลบ inactive refusal |
| `ops/cnyos-staging-controller/scripts/run-activation-contracts.mjs:63` และ `README.md:149` ภายใต้ controller | missing cross-cutting broker test/atomic admission ต้องได้ reviewed replacement พร้อม acceptance ห้ามลด inventory |
| `release-readiness.json:221`, `scripts/verify-production-promotion.mjs:24` | production provenance/protection/external attestation และ patient-data gates ไม่ได้รับการอนุมัติจากแผนนี้ |

## 7. แบบบันทึกการตัดสินใจ — ยังไม่มี sign-off

| สิ่งที่ต้องบันทึก | สถานะ |
| --- | --- |
| Owner อนุญาตให้จัดทำแผนทางเลือก | ได้รับแล้วในแชต ไม่ใช่ release approval |
| Independent security reviewer และผู้ติดต่อ | ยังไม่ยืนยันการรับงาน |
| Risk owner/operator และ alternate | ยังไม่แต่งตั้งสำหรับกระบวนการใหม่ |
| ผู้ดูแล executor/identity/recovery ที่แยกอำนาจ | ยังไม่ระบุ |
| Infrastructure/provider และ capability evidence | ยังไม่เลือก/ตรวจรับ |
| ค่าใช้จ่ายเริ่มต้น/รายเดือน และเพดานงบ | ยังไม่เสนอราคา/อนุมัติ ห้ามซื้อแทน |
| Design digest ที่ผู้ตรวจอิสระลงนามรับรอง พร้อม verdict, conditions และวันที่ | ยังไม่มี sign-off |
| อำนาจ implementation หลัง design ผ่าน | ต้องกำหนดขอบเขตจากแบบที่รับรอง |
| Staging packet / Production approval / real-data admission | ยังไม่มีจากแผนนี้ |

## 8. ขอบเขตการตรวจเอกสารและงานที่ทำจริง

จัดทำแผนจาก controller README/policy, PR36 security checklist, authenticated staging runbook,
production operations runbook และ release-readiness baseline ที่อ่านแล้ว พร้อมการทบทวนแบบแยกโดย AI
AI review นี้ใช้หาช่องว่างของแผน ไม่ใช่ independent human security approval

รอบจัดทำแผนนี้ไม่รัน live SQL ไม่ใช้ credentials ไม่ deploy ไม่แก้ workflow/guard ไม่ push หรือโพสต์ review
ไม่เปลี่ยน NAS/Drive, repo visibility, collaborator permissions หรือ subscription
ไม่ได้รัน application tests ซ้ำสำหรับงานเอกสาร และไม่อ้างว่าหลักฐาน local เดิมพิสูจน์ระบบใหม่

ตรวจพบ source/reference hashes ทั้งเจ็ดไฟล์ยังตรงกับก่อนเขียนแผน และ local Markdown links ทั้งแปดรายการ resolve ได้
ตรวจ whitespace และ `git diff --check` แล้ว; ผลเหล่านี้ตรวจเอกสาร/การไม่เปลี่ยน baseline ไม่ใช่ runtime acceptance
AI review ช่วยแก้ถ้อยคำ network-disabled build, credential custody/TCB, signing ceremony,
database recovery binding, snapshot/time rollback และ closed-world inputs; ไม่ใช่การพิสูจน์ระบบเหล่านั้นแล้ว
การ fetch Supabase changelog แบบ Markdown ไม่รองรับใน web reader จึงเปิด HTML index แทน
ไม่มีการเลือก Supabase feature หรือเปลี่ยน API/schema ในแผนนี้; ก่อน implementation ต้องตรวจ changelog/docs ที่เกี่ยวข้องใหม่

เอกสารอ้างอิงใน workspace:

- [Controller bootstrap](work/controller-boundary-hardening/ops/cnyos-staging-controller/README.md)
- [PR36 security review](work/controller-boundary-hardening/docs/PR36_SECURITY_REVIEW.md)
- [Authenticated staging runbook](work/controller-boundary-hardening/docs/AUTHENTICATED_STAGING_RUNBOOK.md)
- [ACL maintenance protocol](work/controller-boundary-hardening/docs/security/CHANANYA_STAGING_ACL_MAINTENANCE_PROTOCOL.md)
- [Production operations](work/controller-boundary-hardening/docs/PRODUCTION_OPERATIONS_RUNBOOK.md)
- [Release readiness](work/controller-boundary-hardening/release-readiness.json)
- [Deferred requirements](CNYOS-DEPLOY-FIRST-REQUIREMENTS-2026-09-09.md)
- [Engineering checkpoint](CNYOS-CONTROLLER-CHECKPOINT-2026-09-09.md)
