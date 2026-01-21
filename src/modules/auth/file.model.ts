const mongoose = require("mongoose");

const fileSchema = new mongoose.Schema(
  {
    originalName: { type: String, required: true },
    fileName: { type: String, required: true },
    mimeType: { type: String, required: true },
    size: { type: Number, required: true },
    path: { type: String, required: true },

    entityType: { type: String, default: null },
    entityId: { type: String, default: null },

    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },

    isDeleted: { type: Boolean, default: false },
    deletedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model("File", fileSchema);
