import { GlobeViewer } from './globe/GlobeViewer';
import { InspectorPanel } from './panels/InspectorPanel';
import { LayerPanel } from './panels/LayerPanel';
import { StatusBar } from './panels/StatusBar';
import { SearchBar } from './search/SearchBar';

export function App() {
  return (
    <div className="relative h-full w-full">
      <GlobeViewer />
      <div className="pointer-events-none absolute inset-0 flex flex-col">
        <div className="pointer-events-auto mx-auto mt-3 w-full max-w-2xl px-3">
          <SearchBar />
        </div>
        <div className="flex flex-1 items-start justify-between p-3">
          <div className="pointer-events-auto">
            <LayerPanel />
          </div>
          <div className="pointer-events-auto">
            <InspectorPanel />
          </div>
        </div>
        <div className="pointer-events-auto">
          <StatusBar />
        </div>
      </div>
    </div>
  );
}
