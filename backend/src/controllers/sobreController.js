import { prisma } from "../database/client.js";

export const getAboutStats = async (req, res) => {
  try {
    const totalUsers = await prisma.user.count();
    const totalItems = await prisma.item.count();
    const resolvedItems = await prisma.item.count({
      where: { isResolved: true },
    });

    return res.status(200).json({
      message: "Estatísticas carregadas com sucesso.",
      stats: {
        registeredUsers: totalUsers,
        totalItems: totalItems,
        itemsReturned: resolvedItems,
      },
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ error: "Erro ao carregar os dados estatísticos do sistema." });
  }
};
