// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::activation_delivery as delivery;
use crate::activation_store as wire;
impl Store {
    /// Persist the oldest pending intent as exact event bytes before network delivery.
    pub fn delivery_next(
        &mut self,
        scope: &Value,
        registration: &Value,
        now: u64,
    ) -> Result<Option<Value>> {
        let key = wire::raw(scope)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let row: Option<(String,String,Option<String>)> = tx.query_row(
            "SELECT o.id,o.receipt,d.event FROM activation_outbox o LEFT JOIN activation_delivery d ON d.scope=o.scope AND d.id=o.id WHERE o.scope=?1 AND d.acknowledgement IS NULL ORDER BY o.rowid LIMIT 1", [&key],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(storage)?;
        let Some((id, receipt, raw)) = row else {
            return Ok(None);
        };
        if let Some(raw) = raw {
            let e = wire::decoded(&raw)?;
            delivery::registered(&e, registration)?;
            return Ok(Some(e));
        }
        let prior: Option<String> = tx.query_row("SELECT event FROM activation_delivery WHERE scope=?1 ORDER BY sequence DESC LIMIT 1", [&key], |r| r.get(0)).optional().map_err(storage)?;
        let prior = prior.map(|r| wire::decoded(&r)).transpose()?;
        let e = delivery::event(&wire::decoded(&receipt)?, registration, prior.as_ref(), now)?;
        tx.execute(
            "INSERT INTO activation_delivery(scope,id,sequence,event) VALUES(?1,?2,?3,?4)",
            params![
                key,
                id,
                e["sequence"].as_u64().ok_or(Error::InvalidArtifact)?,
                wire::raw(&e)?
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(Some(e))
    }
    /// Retain an exact original Server custody receipt; never erase the intent.
    pub fn delivery_ack(&mut self, scope: &Value, event: &Value, ack: &Value) -> Result<()> {
        delivery::acknowledge(event, ack)?;
        wire::scoped(event, scope)?;
        let key = wire::raw(scope)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (old, prior): (String, Option<String>) = tx
            .query_row(
                "SELECT event,acknowledgement FROM activation_delivery WHERE scope=?1 AND id=?2",
                params![
                    key,
                    event["payload"]["receipt"]["transition"]["id"]
                        .as_str()
                        .ok_or(Error::InvalidArtifact)?
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or(Error::Unauthorized)?;
        let raw = wire::raw(ack)?;
        if old != wire::raw(event)? || prior.is_some_and(|p| p != raw) {
            return Err(Error::InvalidArtifact);
        }
        tx.execute(
            "UPDATE activation_delivery SET acknowledgement=?3 WHERE scope=?1 AND event=?2",
            params![key, old, raw],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(())
    }
}
