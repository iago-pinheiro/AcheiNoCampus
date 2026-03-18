import { prisma } from "../database/client.js";

export const getHome = async (req, res) => {
  try {
    const recentItems = await prisma.item.findMany({
      take: 6,
      orderBy: { createdAt: "desc" },
      include: {
        author: {
          select: { name: true, email: true },
        },
        category: true,
      },
    });

    const lostItems = recentItems.filter((item) => item.status === "LOST");
    const foundItems = recentItems.filter((item) => item.status === "FOUND");

    return res.status(200).json({
      message: "Dados da página inicial carregados com sucesso.",
      data: {
        recentItems,
        lostItems,
        foundItems,
      },
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ error: "Erro ao carregar dados da página inicial." });
  }
};
