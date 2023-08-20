<script lang="ts">
	import Input from '$lib/components/Input.svelte';
	let vita_ip = '';
	let port = 0;
</script>

<div class="h-100% w-100% flex justify-around">
	<section class="flex">
		<form action="" class="m-auto flex flex-col gap-8 items-center p-2">
			<Input
				label="Vita IP"
				bind:value={vita_ip}
				type="text"
				name="vita_ip"
				id="vita_ip"
				placeholder="192.168.1.142"
			/>
			<Input
				label="Port"
				bind:value={port}
				type="number"
				name="port"
				id="port"
				placeholder="5000"
			/>
			<button class="rounded text-white bg-playstation hover:(bg-sky-600 cursor-pointer) border-none py-2 px-6"
				>Connect</button
			>
		</form>
	</section>
	<section class="flex flex-col items-center justify-center">
		<h1 class="text-4xl">VitaPad</h1>
		<p class="text-xl">Connect to your Vita</p>
	</section>
</div>
