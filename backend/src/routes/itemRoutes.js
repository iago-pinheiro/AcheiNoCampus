import { Router } from "express";

const router = Router();

// Rota temporária de teste
router.get("/", (req, res) => {
  res.json({ message: "Rota de itens funcionando!" });
});

export default router;
