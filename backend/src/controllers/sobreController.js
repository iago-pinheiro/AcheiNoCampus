export const getSobreInfo = (req, res) => {
  try {
    const aboutData = {
      title: "O que é o Achei no Campus?",
      description:
        "O Achei no Campus é uma plataforma digital desenvolvida para resolver um problema frequente na nossa faculdade: a perda de objetos pessoais e materiais acadêmicos.",
      mission:
        "Nosso objetivo é criar uma rede de colaboração entre os estudantes. Simplificamos a conexão entre quem perdeu e quem achou, tornando o processo de devolução muito mais rápido e organizado.",
      version: "1.0.0",
    };

    return res.status(200).json({
      message: "Informações do projeto carregadas com sucesso.",
      data: aboutData,
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ error: "Erro ao carregar as informações sobre o projeto." });
  }
};
