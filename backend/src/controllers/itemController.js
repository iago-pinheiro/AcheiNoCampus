import { prisma } from "../database/client.js";

// Criar um novo item
export const createItem = async (req, res) => {
  try {
    const { title, description, categoryId, location, imageUrl, status } =
      req.body;

    const authorId = req.userId;

    const newItem = await prisma.item.create({
      data: {
        title,
        description,
        categoryId,
        location,
        imageUrl,
        status,
        authorId,
      },
    });

    return res
      .status(201)
      .json({ message: "Item registrado com sucesso!", item: newItem });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Erro ao criar o registro do item." });
  }
};

// Listar itens (com suporte a filtros por status e resolução)
export const getItems = async (req, res) => {
  try {
    const { status, isResolved } = req.query;

    const filter = {};
    if (status) filter.status = status;
    if (isResolved !== undefined) filter.isResolved = isResolved === "true";

    const items = await prisma.item.findMany({
      where: filter,
      orderBy: { createdAt: "desc" },
      include: {
        category: true,
        author: {
          select: { id: true, name: true, email: true, ra: true },
        },
      },
    });

    return res.status(200).json(items);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Erro ao buscar a lista de itens." });
  }
};

// Buscar os detalhes de um item específico pelo ID
export const getItemById = async (req, res) => {
  try {
    const { id } = req.params;

    const item = await prisma.item.findUnique({
      where: { id },
      include: {
        category: true,
        author: {
          select: { id: true, name: true, email: true, ra: true },
        },
      },
    });

    if (!item) {
      return res.status(404).json({ error: "Item não encontrado." });
    }

    return res.status(200).json(item);
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ error: "Erro ao buscar os detalhes do item." });
  }
};

// Marcar um item como resolvido
export const resolveItem = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.userId;

    const item = await prisma.item.findUnique({ where: { id } });

    if (!item) {
      return res.status(404).json({ error: "Item não encontrado." });
    }

    if (item.authorId !== userId) {
      return res.status(403).json({
        error: "Você não tem permissão para alterar o status deste item.",
      });
    }

    const updatedItem = await prisma.item.update({
      where: { id },
      data: { isResolved: true },
    });

    return res
      .status(200)
      .json({ message: "Item marcado como resolvido!", item: updatedItem });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ error: "Erro ao atualizar o status do item." });
  }
};
