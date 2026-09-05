---
name: wf-sequence
description: Execute CandyBaked website work as a deterministic A1→A6 workflow from Google Drive source-of-truth through repository-local preview, validation, and Cloudflare publish. Invoke with /WF.Sequence of Work Steps.Sequence of Work Steps.A,A1-A6 or when the user asks to run the CandyBaked A1-A6 sequence. Work mode is not required.
---

# WF SEQUENCE — A1 → A6

Canonical shortcut:

`/WF.Sequence of Work Steps.Sequence of Work Steps.A,A1-A6`

This is a deterministic runbook, not a conversational suggestion and not dependent on ChatGPT Work mode.

## Canonical sources

1. Sequence / page-order source:
   `https://docs.google.com/document/d/11oqBE2kTPajdrXnkH9IwBZAuj6amuvTl9MkRW-e-PNI/edit?usp=drivesdk`
2. A4 product database source:
   `https://docs.google.com/document/d/10pJHPVNCensmTFuhfpUEfNQHvbbY_wJaMeB0h_SnANY/edit?usp=drivesdk`
3. Website repository:
   `Ogenicchocolate21debug/ogenic-chocolate`
4. Cloudflare project:
   `ogenic-chocolate`

## Non-negotiable execution contract

1. Execute strictly in this order: `A1 → A2 → A3 → A4 → A5 → A6`.
2. Never skip a step because another step is already available.
3. Never fabricate a product photo, Thai name, English name, Japanese name, price, category, or ordering position.
4. Google Drive is the source/sync layer. Browser preview and Cloudflare production must use repository-local assets, not private Drive thumbnail URLs.
5. A4 must contain exactly 14 canonical categories in order `01 → 14`. Extra legacy folders are excluded and reported; they are not silently rendered.
6. Build a preview before publish.
7. Run repository validation before Cloudflare build/deploy. Missing required A1–A6 content blocks publish.
8. Do not require Work mode. Use any available Agent/API/MCP/GitHub execution surface that can complete the same deterministic steps.

## Step contract

### A1 — Website Header Video

- Read the A1 Drive source.
- Sync exactly one header video to repository-local storage.
- Canonical runtime path: `assets/website/hero.mp4`.
- Preview must visibly render the video; a broken/blank frame is failure.

### A2 — Second Row, 4 Images

- Read A2 source.
- Sync four images.
- Runtime order must be:
  1. `assets/website/row2-1.png`
  2. `assets/website/row2-2.png`
  3. `assets/website/row2-3.png`
  4. `assets/website/row2-4.png`
- Never reverse the order based on directory listing or upload time.

### A3 — PhotoStory & TextStory

- Read the A3 image source plus Thai and English story text from the Sequence document.
- Sync the story image to repository-local storage.
- Render A3 immediately after A2 and before A4.
- If the image is missing, do not substitute an empty tag or remote Drive placeholder.

### A4 — Product Catalog

Required fields per product record:

`photo + name_th + name_en + name_ja + price`

Rules:

- Read Product Database document as source of truth.
- Render exactly 14 category sections in canonical order.
- Preserve item order inside each category.
- Category navigation/menu must visibly separate all 14 categories.
- Product cards must not be generated from guesses or legacy Shopify data when the canonical database supplies a value.
- If media and database record counts differ, report the exact category and block production when a required record cannot be rendered.

Canonical categories:

1. ชิโอะปัง | Shio Pan | 塩パン
2. ชีสเค้กหน้าไหม้ | Burnt Cheesecake | バスクチーズケーキ
3. ฟัดจ์เค้ก | Fudge Cake | ファッジケーキ
4. บัตเตอร์ครีมเค้ก | Buttercream Cake | バタークリームケーキ
5. โรลเค้ก | Roll Cake | ロールケーキ
6. วาฟเฟิลเค้ก | Waffle Cake | ワッフルケーキ
7. ชิฟฟอนเค้ก | Chiffon Cake | シフォンケーキ
8. บานอฟฟี่ | Banoffee | バノフィー
9. มัฟฟิน & คัพเค้ก | Muffin & Cupcake | マフィン・カップケーキ
10. เค้กปอนด์ | Pound Cake | ホールケーキ
11. ขนมปัง & บัน | Bread & Bun | パン・バンズ
12. ครัวซองต์ & เดนิช | Croissant & Danish | クロワッサン・デニッシュ
13. หมาล่า & ราเม็ง | Mala, Ramen & Thai Noodles | 麻辣・ラーメン・タイ麺
14. เครื่องดื่ม ปั่น & กาแฟ | Drinks, Shakes & Coffee | ドリンク・シェイク・コーヒー

### A5 — Posters

- Sync and render `PT1 → PT18` in numeric order.
- Runtime assets must be repository-local.
- Missing sequence item blocks publish.

### A6 — Story The End

- Sync the final Story The End image.
- Render after A5 as the final content section before footer.
- Missing A6 blocks publish.

## Pipeline

Run in this exact lifecycle:

1. `READ_SEQUENCE_SOURCE`
2. `READ_PRODUCT_DATABASE`
3. `SYNC_ASSETS_TO_REPOSITORY`
4. `NORMALIZE_A1_A6_MANIFEST`
5. `VALIDATE_COUNTS_AND_ORDER`
6. `BUILD_STATIC_PREVIEW`
7. `VISUAL_AND_DATA_QA`
8. `BUILD_CLOUDFLARE_DIST`
9. `PUBLISH_CLOUDFLARE`

## Repository contract

The website repository owns `wf-sequence.manifest.json` as the machine-readable sequence definition and `scripts/validate-wf-sequence.mjs` as the pre-publish gate.

Before publish, run:

`node scripts/validate-wf-sequence.mjs`

On any required missing step or asset, return `BLOCK_PUBLISH` and the exact missing path/category. Never continue to Cloudflare on a failed validation.

## Output contract

Return only:

- `Result`: completed A1–A6 steps and preview/deploy state.
- `Blocked`: exact missing source/asset/category when present.
- `Next`: only the immediate corrective action.
