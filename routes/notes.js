const express = require("express");
const router = express.Router();
var fetchuser = require("../middleware/fetchuser");
const Notes = require("../models/Notes");
const { body, validationResult } = require("express-validator");

// Route 1: fetching all the notes. login required
router.get("/fetchallnotes", fetchuser, async (req, res) => {
  try {
    const notes = await Notes.find({ user: req.user.id });
    res.json(notes);
  } catch (error) {
    console.error(error.message);
    res.status(500).send("some internal error occured");
  }
});

// Route 2: add a new note using: POST "/api/notes/addnotes". login required
router.post(
  "/addnotes",
  fetchuser,
  [
    body("title", "Enter a valid title").isLength({ min: 3 }),
    body("description", "Enter a valid description").isLength({ min: 5 }),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      // if there is error than return bad request
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      const { title, description, tag } = req.body;
      const note = new Notes({
        title,
        description,
        tag,
        user: req.user.id,
      });
      const saveNotes = await note.save();
      res.send(saveNotes);
    } catch (error) {
      console.error(error.message);
      res.status(500).send("some internal error occured");
    }
  }
);

// Route:3 updata the node using : PUT:/api/notes/updatenote/:id . login required
router.put("/updatenote/:id", fetchuser, async (req, res) => {
  try {
    const { title, description, tag } = req.body;
    // create a new note object
    const newNote = {};
    if (title) {
      newNote.title = title;
    }
    if (description) {
      newNote.description = description;
    }
    if (tag) {
      newNote.tag = tag;
    }

    //find the note to update and update it
    let note = await Notes.findById(req.params.id);
    if (!note) {
      return res.status(404).send("not found");
    }
    if (note.user.toString() !== req.user.id) {
      return res.status(401).send("not allowed");
    }
    note = await Notes.findByIdAndUpdate(
      req.params.id,
      { $set: newNote },
      { new: true }
    );
    res.send({ note });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("some internal error occured");
  }
});

// Route 3:deleta a note : delete:/api/notes/deletenote:id . login required

router.delete("/deletenote/:id", fetchuser, async (req, res) => {
  try {
    //find the note to update and update it
    let note = await Notes.findById(req.params.id);
    if (!note) {
      return res.status(404).send("not found");
    }

    // allow deletion if the user owns the note
    if (note.user.toString() !== req.user.id) {
      return res.status(401).send("not allowed");
    }

    note = await Notes.findByIdAndDelete(req.params.id);
    res.json({ note });
    //   res.send("success")
  } catch (error) {
    console.error(error.message);
    res.status(500).send("some internal error occured");
  }
});
module.exports = router;
