import tseslint from "typescript-eslint";

export default tseslint.config(
	...tseslint.configs.strict,
	{
		languageOptions: {
			parserOptions: {
				projectService: true,
				tsconfigRootDir: import.meta.dirname,
			},
		},
		rules: {
			// --- SDL banned functions ---
			"no-eval": "error",
			"no-implied-eval": "error",
			"no-new-func": "error",

			// --- No console in plugin source (use Verdaccio logger) ---
			"no-console": ["error", { allow: ["error"] }],

			// --- Block inline disables — no escape hatches ---
			"no-warning-comments": ["warn", { terms: ["fixme", "hack"] }],

			// --- TypeScript strict rules ---
			"@typescript-eslint/no-explicit-any": "error",
			"@typescript-eslint/no-unsafe-assignment": "error",
			"@typescript-eslint/no-unsafe-call": "error",
			"@typescript-eslint/no-unsafe-member-access": "error",
			"@typescript-eslint/no-unsafe-return": "error",
			"@typescript-eslint/no-unsafe-argument": "error",
			"@typescript-eslint/no-require-imports": "off",

			// --- Block type assertion escape hatches in source ---
			"@typescript-eslint/consistent-type-assertions": ["error", {
				assertionStyle: "as",
				objectLiteralTypeAssertions: "never",
			}],
		},
	},
	// --- Test files: relax casting rules (mocks need it) ---
	{
		files: ["src/__tests__/**/*.ts"],
		rules: {
			"@typescript-eslint/no-unsafe-assignment": "off",
			"@typescript-eslint/no-unsafe-call": "off",
			"@typescript-eslint/no-unsafe-member-access": "off",
			"@typescript-eslint/no-unsafe-return": "off",
			"@typescript-eslint/no-unsafe-argument": "off",
			"@typescript-eslint/consistent-type-assertions": "off",
			"no-console": "off",
		},
	},
);
