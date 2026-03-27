import swaggerJsdoc from "swagger-jsdoc";

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "API AcheiNoCampus",
      version: "1.0.0",
      description:
        "API para gerenciar itens perdidos e achados no campus universitário",
      contact: {
        name: "AcheiNoCampus",
        email: "contato@achenacampus.com",
      },
    },
    servers: [
      {
        url: "http://localhost:3000/api",
        description: "Servidor de desenvolvimento",
      },
      {
        url: "https://api.achenacampus.com/api",
        description: "Servidor de produção",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "Token JWT para autenticação",
        },
      },
    },
  },
  apis: ["./src/routes/*.js"],
};

const specs = swaggerJsdoc(options);

export default specs;
