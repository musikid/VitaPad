import { readable } from 'svelte/store';
import { listen, type Event, type UnlistenFn } from '@tauri-apps/api/event';

enum ConnectionState {
	Disconnected = 'Disconnected',
	Connecting = 'Connecting',
	Connected = 'Connected',
	Disconnecting = 'Disconnecting'
}

interface ConnectionStateEvent {
	state: ConnectionState;
}

const store = readable(ConnectionState.Disconnected, (set) => {
	let unlisten: UnlistenFn | null = null;
	listen('connection_state', (ev: Event<ConnectionStateEvent>) => {
		set(ev.payload.state);
	}).then((un) => {
		unlisten = un;
	});

	return () => {
		unlisten?.();
	};
});

export default store;