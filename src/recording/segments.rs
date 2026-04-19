use anyhow::Result;
use std::path::PathBuf;

pub async fn count_segment_files(out_dir: &PathBuf) -> Result<u64> {
    let mut count = 0u64;
    let mut reader = tokio::fs::read_dir(out_dir).await?;
    while let Some(entry) = reader.next_entry().await? {
        if entry
            .path()
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("mp4"))
            .unwrap_or(false)
        {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}
