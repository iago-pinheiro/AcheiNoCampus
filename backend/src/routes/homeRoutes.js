import { Router } from "express";
import { getHome } from "../controllers/homeController.js";

const router = Router();

/**
 * @swagger
 * /home:
 *   get:
 *     tags:
 *       - Página Inicial
 *     summary: Dados da página inicial
 *     description: Retorna os 6 itens mais recentes divididos por status (perdidos e encontrados). Útil para exibir na página inicial da aplicação
 *     responses:
 *       200:
 *         description: Dados da página inicial carregados com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     recentItems:
 *                       type: array
 *                       description: 6 itens mais recentes
 *                       items:
 *                         type: object
 *                     lostItems:
 *                       type: array
 *                       description: Itens perdidos dos 6 mais recentes
 *                       items:
 *                         type: object
 *                     foundItems:
 *                       type: array
 *                       description: Itens encontrados dos 6 mais recentes
 *                       items:
 *                         type: object
 *       500:
 *         description: Erro ao carregar dados da página inicial
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 */
router.get("/", getHome);

export default router;
