"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { api } from "@/lib/api";

export type Me = { username: string; email: string; role: string; org_id: number } | null;

type Ctx = { me: Me; loading: boolean; isAdmin: boolean; isAnalystUp: boolean };
const MeContext = createContext<Ctx>({ me: null, loading: true, isAdmin: false, isAnalystUp: false });

export function MeProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<Me>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .me()
      .then(setMe)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const isAdmin = me?.role === "admin";
  const isAnalystUp = me?.role === "admin" || me?.role === "analyst";
  return <MeContext.Provider value={{ me, loading, isAdmin, isAnalystUp }}>{children}</MeContext.Provider>;
}

export function useMe(): Ctx {
  return useContext(MeContext);
}
