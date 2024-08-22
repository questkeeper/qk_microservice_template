import initSupabase from "@/utils/initSupabase";
import { Context } from "hono";

export default function initSupabaseMiddleware(
  c: Context<{}, any, {}>,
  next: () => Promise<any>
): Promise<any> {
  initSupabase(c);
  return next();
}
