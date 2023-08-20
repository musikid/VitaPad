<script lang="ts">
	export let label: string;
	export let value: any;

	let focused: boolean = false;
	const onFocus = () => {
		focused = true;
	};
	const onBlur = () => {
		focused = false;
	};
</script>

<div>
	<label for="UserEmail" class:text-blue={focused} class="block text-xs font-medium">
		{label}
	</label>

	<input
		{...$$restProps}
		on:focus={onFocus}
		on:blur={onBlur}
		bind:value
		class="mt-1 bg-gray/15 backdrop-blur border-none w-full rounded-md sm:text-sm"
	/>
</div>
