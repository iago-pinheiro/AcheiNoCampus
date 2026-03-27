import { Router } from "express";
import {
  createItem,
  getItems,
  getItemById,
  resolveItem,
} from "../controllers/itemController.js";
import { verifyToken } from "../../middlewares/authMiddleware.js";

const router = Router();

/**
 * @swagger
 * /items:
 *   get:
 *     tags:
 *       - Itens
 *     summary: Listar todos os itens
 *     description: Retorna uma lista de todos os itens com opções de filtro por status e resolução
 *     parameters:
 *       - name: status
 *         in: query
 *         description: Filtrar por status do item
 *         schema:
 *           type: string
 *           enum: [LOST, FOUND]
 *       - name: isResolved
 *         in: query
 *         description: Filtrar por itens resolvidos (true/false)
 *         schema:
 *           type: string
 *           enum: [true, false]
 *     responses:
 *       200:
 *         description: Lista de itens retornada com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                   title:
 *                     type: string
 *                   description:
 *                     type: string
 *                   category:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       name:
 *                         type: string
 *                   location:
 *                     type: string
 *                   imageUrl:
 *                     type: string
 *                     nullable: true
 *                   status:
 *                     type: string
 *                     enum: [LOST, FOUND]
 *                   isResolved:
 *                     type: boolean
 *                   author:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       name:
 *                         type: string
 *                       email:
 *                         type: string
 *                       ra:
 *                         type: string
 *                         nullable: true
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *                   updatedAt:
 *                     type: string
 *                     format: date-time
 *       500:
 *         description: Erro ao buscar a lista de itens
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 */
router.get("/", getItems);

/**
 * @swagger
 * /items/{id}:
 *   get:
 *     tags:
 *       - Itens
 *     summary: Buscar item por ID
 *     description: Retorna os detalhes completos de um item específico
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: ID do item
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Item encontrado e retornado com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 title:
 *                   type: string
 *                 description:
 *                   type: string
 *                 category:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     name:
 *                       type: string
 *                 location:
 *                   type: string
 *                 imageUrl:
 *                   type: string
 *                   nullable: true
 *                 status:
 *                   type: string
 *                   enum: [LOST, FOUND]
 *                 isResolved:
 *                   type: boolean
 *                 author:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     name:
 *                       type: string
 *                     email:
 *                       type: string
 *                     ra:
 *                       type: string
 *                       nullable: true
 *                 createdAt:
 *                   type: string
 *                   format: date-time
 *                 updatedAt:
 *                   type: string
 *                   format: date-time
 *       404:
 *         description: Item não encontrado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *       500:
 *         description: Erro ao buscar os detalhes do item
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 */
router.get("/:id", getItemById);

// Rotas protegidas - requerem autenticação

/**
 * @swagger
 * /items:
 *   post:
 *     tags:
 *       - Itens
 *     summary: Criar novo item
 *     description: Registra um novo item perdido ou encontrado (requer autenticação com token JWT)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - title
 *               - description
 *               - categoryId
 *               - location
 *               - status
 *             properties:
 *               title:
 *                 type: string
 *                 example: Mochila vermelha
 *                 description: Título/nome do item
 *               description:
 *                 type: string
 *                 example: Mochila vermelha de nylon com alças pretas e logo da marca
 *                 description: Descrição detalhada do item
 *               categoryId:
 *                 type: string
 *                 example: 65a1a1a1a1a1a1a1a1a1a1a
 *                 description: ID da categoria do item
 *               location:
 *                 type: string
 *                 example: Biblioteca Central
 *                 description: Local onde o item foi encontrado ou perdido
 *               imageUrl:
 *                 type: string
 *                 nullable: true
 *                 example: https://exemplo.com/imagem.jpg
 *                 description: URL da imagem do item (opcional)
 *               status:
 *                 type: string
 *                 enum: [LOST, FOUND]
 *                 example: LOST
 *                 description: Status do item (Perdido ou Encontrado)
 *     responses:
 *       201:
 *         description: Item registrado com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 item:
 *                   type: object
 *       401:
 *         description: Token não fornecido ou inválido
 *       500:
 *         description: Erro ao criar o registro do item
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 */
router.post("/", verifyToken, createItem);

/**
 * @swagger
 * /items/{id}/resolve:
 *   patch:
 *     tags:
 *       - Itens
 *     summary: Marcar item como resolvido
 *     description: Marca um item como resolvido (apenas o autor pode fazer isto)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: ID do item a ser marcado como resolvido
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Item marcado como resolvido com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 item:
 *                   type: object
 *       404:
 *         description: Item não encontrado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *       403:
 *         description: Sem permissão - apenas o autor do item pode marcá-lo como resolvido
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *       401:
 *         description: Token não fornecido ou inválido
 *       500:
 *         description: Erro ao atualizar o status do item
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 */
router.patch("/:id/resolve", verifyToken, resolveItem);

export default router;
