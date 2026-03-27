import express from "express";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import specs from "./swaggerConfig.js";
import authRoutes from "./routes/authRoutes.js";
import itemRoutes from "./routes/itemRoutes.js";
import homeRoutes from "./routes/homeRoutes.js";
import sobreRoutes from "./routes/sobreRoutes.js";

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Swagger Documentation
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));

// Rotas da API
app.use("/api/auth", authRoutes);
app.use("/api/items", itemRoutes);
app.use("/api/home", homeRoutes);
app.use("/api/sobre", sobreRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor do Achei no Campus rodando na porta ${PORT}`);
});
