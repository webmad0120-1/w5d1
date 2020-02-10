const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const schemaName = new Schema(
  {
    plaque: String,
    make: String,
    owner: { type : Schema.Types.ObjectId, ref: 'User' },
  },
  {
    timestamps: true
  }
);

const Model = mongoose.model("Car", schemaName);
module.exports = Model;
