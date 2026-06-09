//! 証憑(添付)のブラウザ glue。**wasm32 限定**。
//!
//! `<input type=file>` のファイル読込・暗号化アップロード・復号ダウンロード・ブラウザ保存を仲介する。
//! 暗号は [`iikanji_crypto`] の chunked AEAD (seal/open) を使い、**サーバーへは暗号 blob のみ**出す
//! (CLAUDE.md E2EE 不変条件)。content hash で整合性を確認する。

use uuid::Uuid;
use wasm_bindgen::JsCast;

use iikanji_crypto::{open_attachment, seal_attachment, sha256, DataKey};

use crate::api::Client;

/// `<input type=file>` で選んだ File を bytes に読む。
pub async fn read_file(file: web_sys::File) -> Result<Vec<u8>, String> {
    let blob = gloo_file::Blob::from(file);
    gloo_file::futures::read_as_bytes(&blob)
        .await
        .map_err(|e| format!("ファイル読込に失敗しました: {e}"))
}

/// 平文を chunked AEAD で封緘してアップロードする。
pub async fn upload_attachment(
    client: &Client,
    dk: &DataKey,
    attachment_id: Uuid,
    plaintext: &[u8],
) -> Result<(), String> {
    let blob = seal_attachment(dk, attachment_id.as_bytes(), plaintext);
    client
        .attachment_put(attachment_id, blob)
        .await
        .map_err(|e| e.to_string())
}

/// 添付をダウンロードして復号し、真サイズで切り詰め、content hash を検証して平文を返す。
pub async fn download_attachment(
    client: &Client,
    dk: &DataKey,
    attachment_id: Uuid,
    size: usize,
    expected_hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let blob = client
        .attachment_get(attachment_id)
        .await
        .map_err(|e| e.to_string())?;
    let mut plain = open_attachment(dk, attachment_id.as_bytes(), &blob)
        .map_err(|e| format!("復号に失敗しました: {e}"))?;
    if plain.len() < size {
        return Err("添付データが不足しています".into());
    }
    plain.truncate(size); // chunked blob はゼロ詰め → 真サイズへ
    if &sha256(&plain) != expected_hash {
        return Err("整合性チェックに失敗しました (content hash 不一致)".into());
    }
    Ok(plain)
}

/// bytes をブラウザのダウンロードとして保存させる (Blob → object URL → a.click)。
pub fn trigger_browser_download(bytes: &[u8], filename: &str, mime: &str) -> Result<(), String> {
    let win = web_sys::window().ok_or("window が利用できません")?;
    let doc = win.document().ok_or("document が利用できません")?;
    let array = js_sys::Uint8Array::from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&array);
    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type(mime);
    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &opts)
        .map_err(|e| format!("Blob 生成に失敗しました: {e:?}"))?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)
        .map_err(|e| format!("object URL 生成に失敗しました: {e:?}"))?;
    let anchor = doc
        .create_element("a")
        .map_err(|e| format!("要素生成に失敗しました: {e:?}"))?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| "anchor へのキャストに失敗しました".to_string())?;
    anchor.set_href(&url);
    anchor.set_download(filename);
    anchor.click();
    let _ = web_sys::Url::revoke_object_url(&url);
    Ok(())
}
