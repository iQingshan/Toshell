import { useState, useEffect } from 'react'
import { RefreshCw, Upload, Trash2, FileCode, Package } from 'lucide-react'
import { pluginApi, type Plugin } from '../api'
import './Plugins.css'

export default function Plugins() {
  const [plugins, setPlugins] = useState<Plugin[]>([])
  const [loading, setLoading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [description, setDescription] = useState('')

  const fetchPlugins = async () => {
    setLoading(true)
    try {
      const response = await pluginApi.list()
      setPlugins(response.data.plugins || [])
    } catch (error) {
      console.error('Failed to fetch plugins:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPlugins()
  }, [])

  const handleUpload = async () => {
    if (!selectedFile) return
    setUploading(true)
    try {
      await pluginApi.upload(selectedFile, description)
      setSelectedFile(null)
      setDescription('')
      fetchPlugins()
    } catch (error: any) {
      alert('上传失败: ' + (error.response?.data?.error || error.message))
    } finally {
      setUploading(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('确定要删除此插件吗？')) return
    try {
      await pluginApi.delete(id)
      fetchPlugins()
    } catch (error: any) {
      alert('删除失败: ' + (error.response?.data?.error || error.message))
    }
  }

  const handleRefresh = async () => {
    setLoading(true)
    try {
      const response = await pluginApi.refresh()
      setPlugins(response.data.plugins || [])
    } catch (error) {
      console.error('Failed to refresh plugins:', error)
    } finally {
      setLoading(false)
    }
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'exe': return '🔧'
      case 'dll': return '📦'
      case 'shellcode': return '⚡'
      case 'bof': return '📄'
      default: return '📄'
    }
  }

  const getTypeLabel = (type: string) => {
    switch (type) {
      case 'exe': return 'EXE'
      case 'dll': return 'DLL'
      case 'shellcode': return 'Shellcode'
      case 'bof': return 'BOF'
      default: return type.toUpperCase()
    }
  }

  return (
    <div className="plugins-page">
      <div className="page-header">
        <h1>插件管理</h1>
        <div className="header-actions">
          <button className="refresh-btn" onClick={handleRefresh} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'spin' : ''} />
            刷新
          </button>
        </div>
      </div>

      <div className="upload-section">
        <div className="upload-box">
          <input
            type="file"
            id="plugin-file"
            accept=".exe,.dll,.bin,.raw,.sc,.o,.obj"
            onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
          style={{ display: 'none' }}
          />
          <label htmlFor="plugin-file" className="file-input-label">
            <Upload size={20} />
            <span>{selectedFile ? selectedFile.name : '选择插件文件'}</span>
          </label>
          <input
            type="text"
            placeholder="插件描述（可选）"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="description-input"
          />
          <button
            className="btn-primary"
            onClick={handleUpload}
            disabled={!selectedFile || uploading}
          >
            {uploading ? '上传中...' : '上传插件'}
          </button>
        </div>
        <div className="supported-types">
          支持的类型: EXE | DLL | Shellcode (.bin, .raw, .sc) | BOF (.o, .obj)
        </div>
      </div>

      <div className="plugins-list">
        {loading && plugins.length === 0 ? (
          <div className="loading-state">
            <RefreshCw size={24} className="spin" />
            <span>加载中...</span>
          </div>
        ) : plugins.length === 0 ? (
          <div className="empty-state">
            <Package size={48} />
            <p>暂无插件</p>
            <span>上传插件文件开始使用</span>
          </div>
        ) : (
          <table className="plugins-table">
            <thead>
              <tr>
                <th>类型</th>
                <th>名称</th>
                <th>描述</th>
                <th>大小</th>
                <th>更新时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {plugins.map((plugin) => (
                <tr key={plugin.id}>
                  <td>
                    <span className={`type-badge type-${plugin.type}`}>
                      {getTypeIcon(plugin.type)}
                      {getTypeLabel(plugin.type)}
                    </span>
                  </td>
                  <td>
                    <div className="plugin-name">
                      <FileCode size={16} />
                      <span>{plugin.name}</span>
                    </div>
                  </td>
                  <td>
                    <span className="description">{plugin.description || '-'}</span>
                  </td>
                  <td>
                    <span className="size">{formatSize(plugin.size)}</span>
                  </td>
                  <td>
                    <span className="date">
                      {new Date(plugin.updated_at).toLocaleString()}
                    </span>
                  </td>
                  <td>
                    <div className="actions">
                      <button
                        className="action-btn danger"
                        title="删除"
                        onClick={() => handleDelete(plugin.id)}
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
