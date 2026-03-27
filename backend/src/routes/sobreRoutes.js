import { Router } from "express";
import { getAboutStats } from "../controllers/sobreController.js";

const router = Router();

/**
 * @swagger
 * /sobre:
 *   get:
 *     tags:
 *       - Sobre
 *     summary: Estatísticas do sistema
 *     description: Retorna estatísticas gerais do sistema como total de usuários registrados, total de itens e itens resolvidos
 *     responses:
 *       200:
 *         description: Estatísticas carregadas com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 stats:
 *                   type: object
 *                   properties:
 *                     registeredUsers:
 *                       type: integer
 *                       description: Total de usuários registrados no sistema
 *                       example: 150
 *                     totalItems:
 *                       type: integer
 *                       description: Total de itens registrados (perdidos e encontrados)
 *                       example: 450
 *                     itemsReturned:
 *                       type: integer
 *                       description: Total de itens que foram resolvidos/devolvidos
 *                       example: 120
 *       500:
 *         description: Erro ao carregar os dados estatísticos do sistema
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 */
router.get("/", getAboutStats);

export default router;
