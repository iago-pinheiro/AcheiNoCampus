import { Router } from "express";
import { getAboutStats } from "../controllers/aboutController.js";

const router = Router();

router.get("/", getAboutStats);

export default router;
