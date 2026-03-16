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
			"no-eval": "error",
			"no-implied-eval": "error",
			"no-new-func": "error",
			"no-console": ["error", { allow: ["error"] }],
			"@typescript-eslint/no-require-imports": "off",
		},
	},
);
