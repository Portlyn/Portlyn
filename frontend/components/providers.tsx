"use client";

import { Avatar, Button, Center, Loader, MantineProvider, Modal, PasswordInput, Stack, Text, TextInput } from "@mantine/core";
import { Notifications, notifications } from "@mantine/notifications";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from "react";
import { usePathname, useRouter } from "next/navigation";

import theme from "@/theme";
import {
  getCurrentUser,
  login as loginRequest,
  completeAccountSetup as completeAccountSetupRequest,
  logoutRequest,
  logout as clearAuthStorage
} from "@/lib/auth";
import { setApiToken, setUnauthorizedHandler } from "@/lib/api";
import type { LoginResponse, User } from "@/lib/types";

interface AuthContextValue {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<LoginResponse>;
  completeAuth: (response: LoginResponse) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function Providers({ children }: { children: ReactNode }) {
  return (
    <MantineProvider theme={theme} defaultColorScheme="dark">
      <Notifications position="top-right" />
      <AuthProvider>{children}</AuthProvider>
    </MantineProvider>
  );
}

function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [setupEmail, setSetupEmail] = useState("");
  const [setupPassword, setSetupPassword] = useState("");
  const [setupConfirmPassword, setSetupConfirmPassword] = useState("");
  const [isCompletingSetup, setIsCompletingSetup] = useState(false);
  const router = useRouter();
  const pathname = usePathname();
  const isPublicAuthRoute =
    pathname === "/login" ||
    pathname === "/oidc/callback" ||
    pathname === "/route-login" ||
    pathname === "/route-forbidden";

  const clearSession = useCallback(() => {
    setUser(null);
    setToken(null);
    clearAuthStorage();
  }, []);

  const handleLogout = useCallback(() => {
    void logoutRequest();
    clearSession();
    router.push("/login");
  }, [clearSession, router]);

  const completeAuth = useCallback(
    (response: LoginResponse) => {
      setApiToken(response.token || null);
      setToken(response.token || null);
      setUser(response.user);
      setSetupEmail(response.user.email || "");
      setSetupPassword("");
      setSetupConfirmPassword("");
      notifications.show({
        title: "Signed in",
        message: `Role: ${response.user.role}`,
        color: "success"
      });
    },
    []
  );

  useEffect(() => {
    setUnauthorizedHandler(handleLogout);
    return () => setUnauthorizedHandler(null);
  }, [handleLogout]);

  useEffect(() => {
    getCurrentUser()
      .then((currentUser) => {
        setUser(currentUser);
        setSetupEmail(currentUser.email || "");
      })
      .catch(() => {
        clearSession();
        if (!isPublicAuthRoute) {
          router.replace("/login");
        }
      })
      .finally(() => {
        setIsLoading(false);
      });
  }, [clearSession, isPublicAuthRoute, router]);

  const login = useCallback(
    async (email: string, password: string) => {
      const response = await loginRequest(email, password);
      if (!response.requires_mfa) {
        completeAuth(response);
      } else {
        setUser(response.user);
      }
      return response;
    },
    [completeAuth]
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      token,
      isLoading,
      isAuthenticated: Boolean(user),
      login,
      completeAuth,
      logout: handleLogout
    }),
    [completeAuth, handleLogout, isLoading, login, token, user]
  );

  const requiresAccountSetup = Boolean(user?.must_change_password);

  const handleCompleteAccountSetup = useCallback(async () => {
    if (!user) {
      return;
    }
    if (setupPassword.length < 8) {
      notifications.show({ color: "danger", message: "Password must be at least 8 characters." });
      return;
    }
    if (setupPassword !== setupConfirmPassword) {
      notifications.show({ color: "danger", message: "Passwords do not match." });
      return;
    }
    setIsCompletingSetup(true);
    try {
      const updatedUser = await completeAccountSetupRequest(setupEmail, setupPassword);
      setUser(updatedUser);
      setSetupPassword("");
      setSetupConfirmPassword("");
      notifications.show({ color: "success", message: "Account setup completed" });
    } catch (error) {
      notifications.show({
        color: "danger",
        message: error instanceof Error ? error.message : "Unable to complete account setup."
      });
    } finally {
      setIsCompletingSetup(false);
    }
  }, [setupConfirmPassword, setupEmail, setupPassword, user]);

  return (
    <AuthContext.Provider value={value}>
      <Modal
        opened={requiresAccountSetup}
        onClose={() => undefined}
        closeOnClickOutside={false}
        closeOnEscape={false}
        withCloseButton={false}
        centered
        title="Finish account setup"
      >
        <Stack gap="md">
          <Text c="dimmed" size="sm">
            This account is still using an initial password. Set a new password now and update the email address if needed.
          </Text>
          <TextInput
            label="Email"
            value={setupEmail}
            onChange={(event) => setSetupEmail(event.currentTarget.value)}
            disabled={isCompletingSetup}
          />
          <PasswordInput
            label="New password"
            value={setupPassword}
            onChange={(event) => setSetupPassword(event.currentTarget.value)}
            disabled={isCompletingSetup}
          />
          <PasswordInput
            label="Confirm password"
            value={setupConfirmPassword}
            onChange={(event) => setSetupConfirmPassword(event.currentTarget.value)}
            disabled={isCompletingSetup}
          />
          <Button loading={isCompletingSetup} onClick={() => void handleCompleteAccountSetup()} disabled={!setupEmail || !setupPassword || !setupConfirmPassword}>
            Save and continue
          </Button>
        </Stack>
      </Modal>
      {isPublicAuthRoute || (!isLoading && Boolean(user)) ? (
        children
      ) : (
        <Center mih="100vh">
          <Stack gap="sm" align="center">
            <Loader color="brand" />
            <Text c="dimmed">Loading workspace</Text>
          </Stack>
        </Center>
      )}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within Providers");
  }
  return context;
}

export function UserAvatar() {
  const { user } = useAuth();
  const seed = user?.display_name || user?.username || user?.email || "PL";
  const initials = seed.slice(0, 2).toUpperCase();
  return <Avatar radius="xl" size="sm" color="brand.4">{initials}</Avatar>;
}
