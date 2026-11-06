import { getErrorMessage } from '../lib/utils';
import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Plus,
  Search,
  BookOpen,
  Eye,
  Heart,
  Tag,
  User,
  Calendar,
  FileText,
  Archive,
  Edit,
  Trash2
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { Badge } from '../components/ui/Badge';
import { Skeleton } from '../components/ui/Skeleton';
import { knowledgeService, KnowledgeBase, KnowledgeStats } from '../services/knowledge';
import { KnowledgeForm } from '../components/knowledge/KnowledgeForm';

export function Knowledge() {
  const navigate = useNavigate();
  const [knowledgeList, setKnowledgeList] = useState<KnowledgeBase[]>([]);
  const [stats, setStats] = useState<KnowledgeStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchKeyword, setSearchKeyword] = useState('');
  const searchKeywordRef = useRef('');
  const [selectedCategory, setSelectedCategory] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingKnowledge, setEditingKnowledge] = useState<KnowledgeBase | null>(null);

  const categoryOptions = knowledgeService.getCategoryOptions();
  const typeOptions = knowledgeService.getTypeOptions();
  const statusOptions = knowledgeService.getStatusOptions();

  const fetchKnowledgeList = useCallback(async () => {
    try {
      setLoading(true);
      const response = await knowledgeService.getKnowledgeList({
        page: currentPage,
        page_size: 12,
        keyword: searchKeywordRef.current || undefined,
        category: selectedCategory || undefined,
        type: selectedType || undefined,
        status: selectedStatus || undefined,
        sort_by: 'created_at',
        sort_order: 'desc',
      });
      
      setKnowledgeList(response.data);
      setTotalPages(Math.ceil(response.total / response.page_size));
    } catch (error) {
      console.error('Failed to fetch knowledge list:', error);
    } finally {
      setLoading(false);
    }
  }, [currentPage, selectedCategory, selectedType, selectedStatus]);

  useEffect(() => {
    fetchKnowledgeList();
    fetchStats();
  }, [fetchKnowledgeList]);

  const fetchStats = async () => {
    try {
      const statsData = await knowledgeService.getKnowledgeStats();
      setStats(statsData);
    } catch (error) {
      console.error('Failed to fetch knowledge stats:', error);
    }
  };

  const handleSearch = () => {
    setCurrentPage(1);
    fetchKnowledgeList();
  };

  const handleLike = async (id: number) => {
    try {
      await knowledgeService.likeKnowledge(id);
      // Update the like count in the local state
      setKnowledgeList(prev => prev.map(item =>
        item.id === id ? { ...item, like_count: item.like_count + 1 } : item
      ));
    } catch (error) {
      console.error('Failed to like knowledge:', error);
    }
  };

  const handleEdit = (knowledge: KnowledgeBase) => {
    setEditingKnowledge(knowledge);
  };

  const handleDelete = async (knowledge: KnowledgeBase) => {
    if (!confirm(`确定要删除知识库文章 "${knowledge.title}" 吗？此操作不可撤销。`)) {
      return;
    }

    try {
      await knowledgeService.deleteKnowledge(knowledge.id);
      fetchKnowledgeList(); // Refresh the list
      fetchStats(); // Refresh stats
    } catch (error: unknown) {
      alert(getErrorMessage(error, '删除失败'));
    }
  };

  const handleFormClose = () => {
    setShowCreateForm(false);
    setEditingKnowledge(null);
  };

  const handleFormSuccess = () => {
    setShowCreateForm(false);
    setEditingKnowledge(null);
    fetchKnowledgeList();
    fetchStats();
  };

  const getCategoryBadgeColor = (category: string) => {
    const colors: Record<string, string> = {
      vulnerability: 'bg-red-100 text-red-800',
      security: 'bg-blue-100 text-blue-800',
      tool: 'bg-green-100 text-green-800',
      guide: 'bg-yellow-100 text-yellow-800',
      best_practice: 'bg-purple-100 text-purple-800',
    };
    return colors[category] || 'bg-gray-100 text-gray-800';
  };

  const getSeverityBadgeColor = (severity: string) => {
    const colors: Record<string, string> = {
      low: 'bg-green-100 text-green-800',
      medium: 'bg-yellow-100 text-yellow-800',
      high: 'bg-orange-100 text-orange-800',
      critical: 'bg-red-100 text-red-800',
    };
    return colors[severity] || 'bg-gray-100 text-gray-800';
  };

  if (loading && knowledgeList.length === 0) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <Skeleton className="h-8 w-32" />
          <Skeleton className="h-10 w-24" />
        </div>
        
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <Skeleton className="h-4 w-16 mb-2" />
                <Skeleton className="h-8 w-12" />
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {[...Array(6)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <Skeleton className="h-6 w-full mb-4" />
                <Skeleton className="h-4 w-full mb-2" />
                <Skeleton className="h-4 w-3/4 mb-4" />
                <div className="flex gap-2">
                  <Skeleton className="h-6 w-16" />
                  <Skeleton className="h-6 w-20" />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-in fade-in-0 duration-500">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
            <BookOpen className="h-8 w-8 text-blue-600" />
            知识库管理
          </h1>
          <p className="text-gray-600 mt-1">管理和浏览安全知识库内容</p>
        </div>
        <Button 
          onClick={() => setShowCreateForm(true)}
          className="flex items-center gap-2"
        >
          <Plus className="h-4 w-4" />
          新建知识
        </Button>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card className="animate-in slide-in-from-left-1 duration-500">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">总计</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.total_count}</p>
                </div>
                <div className="p-3 bg-blue-100 rounded-full">
                  <BookOpen className="h-6 w-6 text-blue-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="animate-in slide-in-from-left-2 duration-500 delay-100">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">已发布</p>
                  <p className="text-2xl font-bold text-green-600">{stats.published_count}</p>
                </div>
                <div className="p-3 bg-green-100 rounded-full">
                  <FileText className="h-6 w-6 text-green-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="animate-in slide-in-from-left-3 duration-500 delay-200">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">草稿</p>
                  <p className="text-2xl font-bold text-yellow-600">{stats.draft_count}</p>
                </div>
                <div className="p-3 bg-yellow-100 rounded-full">
                  <Edit className="h-6 w-6 text-yellow-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="animate-in slide-in-from-left-4 duration-500 delay-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">已归档</p>
                  <p className="text-2xl font-bold text-gray-600">{stats.archived_count}</p>
                </div>
                <div className="p-3 bg-gray-100 rounded-full">
                  <Archive className="h-6 w-6 text-gray-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Search and Filters */}
      <Card>
        <CardContent className="p-6">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
                <Input
                  placeholder="搜索知识库内容..."
                  value={searchKeyword}
                  onChange={(e) => {
                    searchKeywordRef.current = e.target.value;
                    setSearchKeyword(e.target.value);
                  }}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  className="pl-10"
                />
              </div>
            </div>
            
            <div className="flex gap-2">
              <Select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                options={[
                  { value: '', label: '所有分类' },
                  ...categoryOptions
                ]}
                className="w-32"
              />
              
              <Select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                options={[
                  { value: '', label: '所有类型' },
                  ...typeOptions
                ]}
                className="w-32"
              />
              
              <Select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                options={[
                  { value: '', label: '所有状态' },
                  ...statusOptions
                ]}
                className="w-32"
              />
              
              <Button onClick={handleSearch} className="flex items-center gap-2">
                <Search className="h-4 w-4" />
                搜索
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Knowledge List */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {knowledgeList.map((knowledge, index) => (
          <Card
            key={knowledge.id}
            className={`hover:shadow-lg transition-shadow cursor-pointer animate-in slide-in-from-bottom-4 duration-500`}
            style={{ animationDelay: `${index * 100}ms` }}
            onClick={() => navigate(`/knowledge/${knowledge.id}`)}
          >
            <CardHeader className="pb-3">
              <div className="flex justify-between items-start">
                <CardTitle
                  className="text-lg line-clamp-2 hover:text-blue-600 transition-colors cursor-pointer"
                  onClick={(e) => {
                    e.stopPropagation();
                    navigate(`/knowledge/${knowledge.id}`);
                  }}
                >
                  {knowledge.title}
                </CardTitle>
                <div className="flex gap-1 ml-2">
                  <Badge className={getCategoryBadgeColor(knowledge.category)}>
                    {knowledge.category_text}
                  </Badge>
                  {knowledge.severity && (
                    <Badge className={getSeverityBadgeColor(knowledge.severity)}>
                      {knowledge.severity_text}
                    </Badge>
                  )}
                </div>
              </div>
            </CardHeader>
            
            <CardContent className="pt-0">
              <p className="text-gray-600 text-sm line-clamp-3 mb-4">
                {knowledge.summary || knowledge.content.substring(0, 150) + '...'}
              </p>
              
              <div className="flex flex-wrap gap-1 mb-4">
                {(knowledge.tags || []).slice(0, 3).map((tag) => (
                  <Badge key={tag.id} variant="outline" className="text-xs">
                    <Tag className="h-3 w-3 mr-1" />
                    {tag.display_name}
                  </Badge>
                ))}
                {(knowledge.tags || []).length > 3 && (
                  <Badge variant="outline" className="text-xs">
                    +{(knowledge.tags || []).length - 3}
                  </Badge>
                )}
              </div>
              
              <div className="flex items-center justify-between text-sm text-gray-500">
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-1">
                    <Eye className="h-4 w-4" />
                    {knowledge.view_count}
                  </div>
                  <button 
                    onClick={(e) => {
                      e.stopPropagation();
                      handleLike(knowledge.id);
                    }}
                    className="flex items-center gap-1 hover:text-red-500 transition-colors"
                  >
                    <Heart className="h-4 w-4" />
                    {knowledge.like_count}
                  </button>
                </div>
                
                <div className="flex items-center gap-1">
                  <User className="h-4 w-4" />
                  {knowledge.author.real_name}
                </div>
              </div>
              
              <div className="flex items-center justify-between mt-3 pt-3 border-t">
                <div className="flex items-center gap-1 text-xs text-gray-500">
                  <Calendar className="h-3 w-3" />
                  {new Date(knowledge.created_at).toLocaleDateString('zh-CN')}
                </div>
                
                <div className="flex gap-1">
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 px-2"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleEdit(knowledge);
                    }}
                  >
                    <Edit className="h-3 w-3" />
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 px-2 text-red-600 hover:text-red-700"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDelete(knowledge);
                    }}
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
          <Button
            variant="outline"
            disabled={currentPage === 1}
            onClick={() => setCurrentPage(prev => prev - 1)}
          >
            上一页
          </Button>
          
          <div className="flex items-center gap-1">
            {[...Array(Math.min(5, totalPages))].map((_, i) => {
              const page = i + 1;
              return (
                <Button
                  key={page}
                  variant={currentPage === page ? "default" : "outline"}
                  onClick={() => setCurrentPage(page)}
                  className="w-10 h-10"
                >
                  {page}
                </Button>
              );
            })}
          </div>
          
          <Button
            variant="outline"
            disabled={currentPage === totalPages}
            onClick={() => setCurrentPage(prev => prev + 1)}
          >
            下一页
          </Button>
        </div>
      )}

      {/* Knowledge Form Modal */}
      {(showCreateForm || editingKnowledge) && (
        <KnowledgeForm
          knowledge={editingKnowledge || undefined}
          onClose={handleFormClose}
          onSuccess={handleFormSuccess}
        />
      )}
    </div>
  );
}
