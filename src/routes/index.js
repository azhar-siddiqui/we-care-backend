import { Router } from "express";
import AdminRoutes from "./admin.routes.js";

const routes = Router();

routes.use("/api/v1/auth", AdminRoutes);

export default routes;
