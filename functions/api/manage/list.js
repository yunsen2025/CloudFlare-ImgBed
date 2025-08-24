import { readIndex, mergeOperationsToIndex, deleteAllOperations, rebuildIndex,
    getIndexInfo, getIndexStorageStats } from '../../utils/indexManager.js';
import { getDatabase } from '../../utils/databaseAdapter.js';

export async function onRequest(context) {
    const { request, waitUntil } = context;
    const url = new URL(request.url);

    // 解析查询参数
    let start = parseInt(url.searchParams.get('start'), 10) || 0;
    let count = parseInt(url.searchParams.get('count'), 10) || 50;
    let sum = url.searchParams.get('sum') === 'true';
    let recursive = url.searchParams.get('recursive') === 'true';
    let dir = url.searchParams.get('dir') || '';
    let search = url.searchParams.get('search') || '';
    let channel = url.searchParams.get('channel') || '';
    let listType = url.searchParams.get('listType') || '';
    let action = url.searchParams.get('action') || '';

    // 处理搜索关键字
    if (search) {
        search = decodeURIComponent(search).trim();
    }

    // 处理目录参数
    if (dir.startsWith('/')) {
        dir = dir.substring(1);
    }
    if (dir && !dir.endsWith('/')) {
        dir += '/';
    }

    try {
        // 特殊操作：重建索引
        if (action === 'rebuild') {
            waitUntil(rebuildIndex(context, (processed) => {
                console.log(`Rebuilt ${processed} files...`);
            }));

            return new Response('Index rebuilt asynchronously', {
                headers: { "Content-Type": "text/plain" }
            });
        }

        // 特殊操作：合并挂起的原子操作到索引
        if (action === 'merge-operations') {
            waitUntil(mergeOperationsToIndex(context));

            return new Response('Operations merged into index asynchronously', {
                headers: { "Content-Type": "text/plain" }
            });
        }

        // 特殊操作：清除所有原子操作
        if (action === 'delete-operations') {
            waitUntil(deleteAllOperations(context));

            return new Response('All operations deleted asynchronously', {
                headers: { "Content-Type": "text/plain" }
            });
        }

        // 特殊操作：获取索引存储信息
        if (action === 'index-storage-stats') {
            const stats = await getIndexStorageStats(context);
            return new Response(JSON.stringify(stats), {
                headers: { "Content-Type": "application/json" }
            });
        }

        // 特殊操作：获取索引信息
        if (action === 'info') {
            const info = await getIndexInfo(context);
            return new Response(JSON.stringify(info), {
                headers: { "Content-Type": "application/json" }
            });
        }

        // 普通查询：只返回总数
        if (count === -1 && sum) {
            const result = await readIndex(context, {
                search,
                directory: dir,
                channel,
                listType,
                countOnly: true
            });
            
            return new Response(JSON.stringify({ 
                sum: result.totalCount,
                indexLastUpdated: result.indexLastUpdated 
            }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        // 普通查询：返回数据
        const result = await readIndex(context, {
            search,
            directory: dir,
            start,
            count,
            channel,
            listType,
            includeSubdirFiles: recursive,
        });

        // 索引读取失败，直接从 KV 中获取所有文件记录
        if (!result.success) {
            const dbRecords = await getAllFileRecords(context.env, dir);
            
            return new Response(JSON.stringify({
                files: dbRecords.files,
                directories: dbRecords.directories,
                totalCount: dbRecords.totalCount,
                returnedCount: dbRecords.returnedCount,
                indexLastUpdated: Date.now(),
                isIndexedResponse: false // 标记这是来自 KV 的响应
            }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        // 转换文件格式
        const compatibleFiles = result.files.map(file => ({
            name: file.id,
            metadata: file.metadata
        }));

        return new Response(JSON.stringify({
            files: compatibleFiles,
            directories: result.directories,
            totalCount: result.totalCount,
            returnedCount: result.returnedCount,
            indexLastUpdated: result.indexLastUpdated,
            isIndexedResponse: true // 标记这是来自索引的响应
        }), {
            headers: { "Content-Type": "application/json" }
        });

    } catch (error) {
        console.error('Error in list-indexed API:', error);
        return new Response(JSON.stringify({
            error: 'Internal server error',
            message: error.message
        }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }
}

async function getAllFileRecords(env, dir) {
    const allRecords = [];
    let cursor = null;

    try {
        const db = getDatabase(env);

        while (true) {
            const response = await db.list({
                prefix: dir,
                limit: 1000,
                cursor: cursor
            });

            // 检查响应格式
            if (!response || !response.keys || !Array.isArray(response.keys)) {
                console.error('Invalid response from database list:', response);
                break;
            }

            cursor = response.cursor;

            for (const item of response.keys) {
                // 跳过管理相关的键
                if (item.name.startsWith('manage@') || item.name.startsWith('chunk_')) {
                    continue;
                }

                // 跳过没有元数据的文件
                if (!item.metadata || !item.metadata.TimeStamp) {
                    continue;
                }

                allRecords.push(item);
            }

            if (!cursor) break;
            
            // 添加协作点
            await new Promise(resolve => setTimeout(resolve, 10));
        }

        // 提取目录信息
        const directories = new Set();
        const filteredRecords = [];
        allRecords.forEach(item => {
            const subDir = item.name.substring(dir.length);
            const firstSlashIndex = subDir.indexOf('/');
            if (firstSlashIndex !== -1) {
                directories.add(dir + subDir.substring(0, firstSlashIndex));
            } else {
                filteredRecords.push(item);
            }
        });

        return {
            files: filteredRecords,
            directories: Array.from(directories),
            totalCount: allRecords.length,
            returnedCount: filteredRecords.length
        };

    } catch (error) {
        console.error('Error in getAllFileRecords:', error);
        return {
            files: [],
            directories: [],
            totalCount: 0,
            returnedCount: 0,
            error: error.message
        };
    }
}