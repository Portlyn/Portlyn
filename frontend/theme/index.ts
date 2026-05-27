import { createTheme } from "@mantine/core";

const theme = createTheme({
  primaryColor: "brand",
  primaryShade: 5,
  autoContrast: true,
  defaultRadius: "lg",
  fontFamily: "Inter, Segoe UI, Arial, sans-serif",
  headings: {
    fontFamily: "Inter, Segoe UI, Arial, sans-serif",
    fontWeight: "600",
    sizes: {
      h1: { fontSize: "2rem", lineHeight: "1.05" },
      h2: { fontSize: "1.5rem", lineHeight: "1.1" },
      h3: { fontSize: "1.125rem", lineHeight: "1.2" }
    }
  },
  colors: {
    brand: [
      "#f5f0fc",
      "#e8def5",
      "#d4c1ec",
      "#b89ade",
      "#9c79d0",
      "#6a4a99",
      "#553a7e",
      "#422c63",
      "#2f1f48",
      "#1d1330"
    ],
    success: [
      "#e9faf3",
      "#ccf3e0",
      "#9ce8c2",
      "#69dca3",
      "#3fd28a",
      "#22c97a",
      "#179c5e",
      "#0e7a48",
      "#075833",
      "#03361f"
    ],
    warning: [
      "#fff6e5",
      "#ffe8bf",
      "#fcd58c",
      "#fac15a",
      "#f8b13a",
      "#f6a522",
      "#cd8413",
      "#a3660c",
      "#794907",
      "#502d03"
    ],
    danger: [
      "#fdecec",
      "#f9cccc",
      "#f3a1a1",
      "#ed7575",
      "#ea5050",
      "#e63d3d",
      "#bd2a2a",
      "#931e1e",
      "#691414",
      "#400a0a"
    ],
    info: [
      "#e6f5ff",
      "#bee2ff",
      "#8fccff",
      "#5cb5ff",
      "#34a3ff",
      "#1493ee",
      "#0a74c0",
      "#055691",
      "#023b65",
      "#01233e"
    ],
    accent: [
      "#e8fbfa",
      "#c2f4f0",
      "#8fe8e2",
      "#5edcd3",
      "#37d2c7",
      "#1ac9bc",
      "#0d9d92",
      "#077871",
      "#035351",
      "#012f30"
    ],
    dark: [
      "#d5d9e2",
      "#b6bdcc",
      "#8d96a8",
      "#6a7282",
      "#4d5463",
      "#292c33",
      "#1f1f23",
      "#1a1b1e",
      "#121316",
      "#0d0e11"
    ]
  },
  black: "#0d0e11",
  white: "#f4f7fb",
  defaultGradient: {
    from: "brand.4",
    to: "brand.6",
    deg: 135
  },
  components: {
    AppShell: {
      styles: {
        main: {
          background: "#121316"
        }
      }
    },
    Paper: {
      defaultProps: {
        radius: "lg",
        p: "lg"
      },
      styles: {
        root: {
          backgroundColor: "#1f1f23",
          boxShadow: "0 18px 40px -28px rgba(0, 0, 0, 0.9)"
        }
      }
    },
    Card: {
      defaultProps: {
        radius: "lg",
        p: "lg"
      },
      styles: {
        root: {
          backgroundColor: "#1f1f23",
          boxShadow: "0 18px 40px -28px rgba(0, 0, 0, 0.9)"
        }
      }
    },
    Button: {
      defaultProps: {
        radius: "md"
      },
      styles: {
        root: {
          fontWeight: 600,
          letterSpacing: "-0.005em"
        }
      }
    },
    NavLink: {
      defaultProps: {
        variant: "subtle"
      },
      styles: {
        root: {
          borderRadius: "12px",
          color: "#9aa3b2"
        },
        label: {
          fontSize: "0.9rem",
          fontWeight: 500
        },
        section: {
          color: "#7e8795"
        }
      }
    },
    TextInput: {
      defaultProps: {
        size: "md"
      }
    },
    PasswordInput: {
      defaultProps: {
        size: "md"
      }
    },
    Select: {
      defaultProps: {
        size: "md"
      }
    },
    NumberInput: {
      defaultProps: {
        size: "md"
      }
    },
    Avatar: {
      defaultProps: {
        color: "brand.4",
        variant: "light"
      },
      styles: {
        placeholder: {
          fontWeight: 600
        }
      }
    },
    Table: {
      styles: {
        table: {
          backgroundColor: "transparent"
        },
        th: {
          borderBottom: "none",
          color: "#7e8795",
          fontSize: "0.7rem",
          fontWeight: 600,
          letterSpacing: "0.08em",
          textTransform: "uppercase"
        },
        td: {
          borderTop: "1px solid rgba(255, 255, 255, 0.04)"
        },
        tr: {
          backgroundColor: "transparent"
        }
      }
    },
    Badge: {
      defaultProps: {
        radius: "sm",
        variant: "light"
      },
      styles: {
        root: {
          fontWeight: 600,
          letterSpacing: "0.02em",
          textTransform: "none"
        }
      }
    },
    Modal: {
      styles: {
        content: {
          backgroundColor: "#292a2d",
          boxShadow: "0 24px 60px -30px rgba(0, 0, 0, 0.85)"
        },
        header: {
          backgroundColor: "#292a2d"
        }
      }
    },
    Drawer: {
      styles: {
        content: {
          backgroundColor: "#292a2d"
        },
        header: {
          backgroundColor: "#292a2d"
        },
        body: {
          paddingTop: "0.25rem"
        }
      }
    }
  }
});

export default theme;
