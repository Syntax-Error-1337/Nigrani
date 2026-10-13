/// Bounded `?limit=&offset=` pagination for list endpoints.
/// Offset is capped so deep paging cannot scan the whole table.
/// NOTE: keep fields inline on each filter struct — `#[serde(flatten)]`
/// breaks `serde_urlencoded` number coercion in axum `Query`.
pub fn resolve(
    limit: Option<i64>,
    offset: Option<i64>,
    default_limit: i64,
) -> crate::core::AppResult<(i64, i64)> {
    let limit = limit.unwrap_or(default_limit).clamp(1, 200);
    let offset = offset.unwrap_or(0);
    if !(0..=10_000).contains(&offset) {
        return Err(crate::core::AppError::BadRequest(
            "offset must be between 0 and 10000".to_owned(),
        ));
    }
    Ok((limit, offset))
}
