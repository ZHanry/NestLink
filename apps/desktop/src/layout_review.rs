//! CI-only capture of synthetic egui frames for visual review; never reads a desktop.
#![allow(clippy::expect_used)]
use base64::{Engine, engine::general_purpose::STANDARD};
use eframe::egui;
use serde_json::json;
use std::{collections::BTreeMap, path::Path};

#[derive(Default)]
pub(super) struct ReviewCapture {
    textures: BTreeMap<String, Texture>,
}
struct Texture {
    size: [usize; 2],
    rgba: Vec<u8>,
}
impl ReviewCapture {
    pub(super) fn frame(&mut self, output: &egui::FullOutput) {
        for (id, delta) in &output.textures_delta.set {
            let egui::ImageData::Color(image) = &delta.image;
            let id = format!("{id:?}");
            if delta.pos.is_none() {
                self.textures.insert(
                    id.clone(),
                    Texture {
                        size: image.size,
                        rgba: vec![0; image.size[0] * image.size[1] * 4],
                    },
                );
            }
            if let Some(texture) = self.textures.get_mut(&id) {
                let [x, y] = delta.pos.unwrap_or([0, 0]);
                for row in 0..image.size[1] {
                    for column in 0..image.size[0] {
                        let target = ((y + row) * texture.size[0] + x + column) * 4;
                        texture.rgba[target..target + 4].copy_from_slice(
                            &image.pixels[row * image.size[0] + column].to_array(),
                        );
                    }
                }
            }
        }
    }

    pub(super) fn write(&self, context: &egui::Context, output: &egui::FullOutput, path: &Path) {
        let primitives = context.tessellate(output.shapes.clone(), output.pixels_per_point);
        let meshes: Vec<_> = primitives.iter().filter_map(|primitive| {
            let egui::epaint::Primitive::Mesh(mesh) = &primitive.primitive else { return None; };
            Some(json!({
                "clip": [primitive.clip_rect.min.x, primitive.clip_rect.min.y, primitive.clip_rect.max.x, primitive.clip_rect.max.y],
                "texture": format!("{:?}",mesh.texture_id),
                "vertices": mesh.vertices.iter().map(|vertex| json!([vertex.pos.x,vertex.pos.y,vertex.uv.x,vertex.uv.y,vertex.color.to_array()])).collect::<Vec<_>>(),
                "indices": mesh.indices,
            }))
        }).collect();
        let textures: BTreeMap<_, _> = self
            .textures
            .iter()
            .map(|(id, texture)| {
                (
                    id,
                    json!({"size":texture.size,"rgba":STANDARD.encode(&texture.rgba)}),
                )
            })
            .collect();
        let value = json!({"kind":"synthetic-egui-frame", "pixels_per_point":output.pixels_per_point,"textures":textures,"meshes":meshes});
        std::fs::write(path, serde_json::to_vec(&value).expect("review JSON"))
            .expect("review frame");
    }
}
