pub mod socket;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    pub id: Uuid,
    pub name: String,
    pub participant_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomCreateRequest {
    pub name: String,
    pub participant_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomResponse {
    pub id: Uuid,
    pub name: String,
    pub participants: Vec<RoomParticipant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomParticipant {
    pub user_id: Uuid,
    pub username: String,
    pub public_key: Option<String>,
}

impl Room {
    pub fn new(name: String, participant_ids: Vec<Uuid>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            participant_ids,
        }
    }
}