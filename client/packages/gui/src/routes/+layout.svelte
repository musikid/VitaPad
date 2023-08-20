<script>
	import 'virtual:uno.css';
	import './styles.css';
</script>

<main id="app">
	<slot />
</main>

<style lang="postcss">
	#app {
		@apply h-100\%;
	}
</style>
