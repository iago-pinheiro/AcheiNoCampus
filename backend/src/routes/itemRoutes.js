import { Router } from "express";
import {
  createItem,
  getItems,
  getItemById,
  resolveItem,
} from "../controllers/itemController.js";
import { verifyToken } from "../middlewares/authMiddleware.js";

const router = Router();

// Rotas Públicas
router.get("/", getItems);
router.get("/:id", getItemById);

// Rotas Privadas

router.post("/", verifyToken, createItem);
router.patch("/:id/resolve", verifyToken, resolveItem);

export default router;
