import { Router } from "express";
import { getSobreInfo } from "../controllers/sobreController.js";

const router = Router();

router.get("/", getSobreInfo);

export default router;
