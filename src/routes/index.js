import { Router } from "express";
import AdminRoutes from "./admin.routes.js";

const routes = Router();

routes.use("/api/auth", AdminRoutes);

export default routes;
