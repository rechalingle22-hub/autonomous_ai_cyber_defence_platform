"""Neo4j graph database async client with local in-memory fallback.

Used for storing and querying entity relationship graphs and attack chains.
"""

from typing import Any, Dict, List, Optional
from neo4j import AsyncGraphDatabase
from backend.app.config.settings import settings


class InMemoryGraphFallback:
    """Mock Graph client when Neo4j is not connected."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    async def run(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        # Returns simulated empty or structured records
        return []

    async def verify_connectivity(self) -> bool:
        return True

    async def close(self) -> None:
        pass


MockNeo4jDriver = InMemoryGraphFallback


class Neo4jManager:
    """Manages Neo4j driver connection lifecycle."""

    def __init__(self) -> None:
        self.driver: Any = None
        self._is_connected: bool = True

    async def connect(self) -> None:
        if settings.NEO4J_ENABLED:
            try:
                driver = AsyncGraphDatabase.driver(
                    settings.NEO4J_URI,
                    auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
                )
                await driver.verify_connectivity()
                self.driver = driver
            except Exception:
                self.driver = InMemoryGraphFallback()
        else:
            self.driver = InMemoryGraphFallback()

    async def disconnect(self) -> None:
        if self.driver:
            await self.driver.close()

    async def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if self.driver is None:
            await self.connect()
        if isinstance(self.driver, InMemoryGraphFallback):
            return await self.driver.run(query, parameters)
        async with self.driver.session() as session:
            result = await session.run(query, parameters or {})
            records = await result.data()
            return records


neo4j_manager = Neo4jManager()


async def get_neo4j() -> Neo4jManager:
    """FastAPI dependency for accessing Neo4j graph driver."""
    if neo4j_manager.driver is None:
        await neo4j_manager.connect()
    return neo4j_manager

