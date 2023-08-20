import { defineConfig } from 'unocss';
import presetWebFonts from '@unocss/preset-web-fonts';
import presetUno from '@unocss/preset-uno';
import transformerDirectives from '@unocss/transformer-directives';
import transformerVariantGroup from '@unocss/transformer-variant-group';
import { presetForms } from '@julr/unocss-preset-forms';

export default defineConfig({
	presets: [
		presetWebFonts({
			provider: 'bunny',
			inlineImports: true,
			fonts: {
				serif: ['Lora', 'Merriweather'],
				sans: ['Inter:200,300,400,500,600,700', 'Fira Sans'],
				mono: ['JetBrains Mono', 'Fira Code']
			}
		}),
		presetForms(),
		presetUno()
	],
	transformers: [transformerDirectives(), transformerVariantGroup()],
	theme: {
		colors: {
			playstation: '#003791'
		}
	}
});
