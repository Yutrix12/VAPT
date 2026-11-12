import type { RouteObject } from 'react-router'
import { HomePage } from './home/HomePage'
import { NotFoundPage } from './home/NotFoundPage'
import { tools } from './tools/registry'
import { Shell } from './Shell'

/** Home, one route per ready tool in the registry, and Not found. */
export const appRoutes: RouteObject[] = [
  {
    element: <Shell />,
    children: [
      { path: '/', element: <HomePage /> },
      ...tools.flatMap((tool) => {
        if (tool.status !== 'ready') return []
        const Page = tool.page
        return [{ path: tool.path, element: <Page /> }]
      }),
      { path: '*', element: <NotFoundPage /> },
    ],
  },
]
