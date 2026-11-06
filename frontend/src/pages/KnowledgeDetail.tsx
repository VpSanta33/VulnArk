import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  ArrowLeft, 
  Eye, 
  Heart, 
  Tag, 
  User, 
  Calendar, 
  Edit, 
  Share2, 
  BookOpen,
  Clock,
  CheckCircle,
  Archive,
  AlertTriangle
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Skeleton } from '../components/ui/Skeleton';
import { knowledgeService, KnowledgeBase } from '../services/knowledge';
import { KnowledgeContentRenderer } from '../components/viewer/KnowledgeContentRenderer';

export function KnowledgeDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [knowledge, setKnowledge] = useState<KnowledgeBase | null>(null);
  const [relatedKnowledge, setRelatedKnowledge] = useState<KnowledgeBase[]>([]);
  const [loading, setLoading] = useState(true);
  const [liked, setLiked] = useState(false);

  useEffect(() => {
    if (id) {
      fetchKnowledgeDetail(parseInt(id));
      fetchRelatedKnowledge(parseInt(id));
    }
  }, [id]);

  const fetchKnowledgeDetail = async (knowledgeId: number) => {
    try {
      setLoading(true);
      const data = await knowledgeService.getKnowledgeById(knowledgeId);
      setKnowledge(data);
    } catch (error) {
      console.error('Failed to fetch knowledge detail:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchRelatedKnowledge = async (knowledgeId: number) => {
    try {
      const data = await knowledgeService.getRelatedKnowledge(knowledgeId, 5);
      setRelatedKnowledge(data);
    } catch (error) {
      console.error('Failed to fetch related knowledge:', error);
    }
  };

  const handleLike = async () => {
    if (!knowledge) return;
    
    try {
      await knowledgeService.likeKnowledge(knowledge.id);
      setKnowledge(prev => prev ? { ...prev, like_count: prev.like_count + 1 } : null);
      setLiked(true);
    } catch (error) {
      console.error('Failed to like knowledge:', error);
    }
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

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'published':
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'draft':
        return <Edit className="h-4 w-4 text-yellow-600" />;
      case 'archived':
        return <Archive className="h-4 w-4 text-gray-600" />;
      default:
        return <Clock className="h-4 w-4 text-gray-600" />;
    }
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-10 w-20" />
          <Skeleton className="h-8 w-64" />
        </div>
        
        <div className="grid gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2 space-y-6">
            <Card>
              <CardHeader>
                <Skeleton className="h-8 w-full" />
                <div className="flex gap-2 mt-4">
                  <Skeleton className="h-6 w-20" />
                  <Skeleton className="h-6 w-16" />
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-3/4" />
                </div>
              </CardContent>
            </Card>
          </div>
          
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <Skeleton className="h-6 w-24" />
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-2/3" />
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    );
  }

  if (!knowledge) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px]">
        <AlertTriangle className="h-16 w-16 text-gray-400 mb-4" />
        <h2 className="text-xl font-semibold text-gray-900 mb-2">知识库不存在</h2>
        <p className="text-gray-600 mb-4">您访问的知识库内容不存在或已被删除</p>
        <Button onClick={() => navigate('/knowledge')}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          返回知识库
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-in fade-in-0 duration-500">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button 
            variant="outline" 
            onClick={() => navigate('/knowledge')}
            className="flex items-center gap-2"
          >
            <ArrowLeft className="h-4 w-4" />
            返回
          </Button>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
              <BookOpen className="h-6 w-6 text-blue-600" />
              {knowledge.title}
            </h1>
            <div className="flex items-center gap-4 mt-2 text-sm text-gray-600">
              <div className="flex items-center gap-1">
                <User className="h-4 w-4" />
                {knowledge.author.real_name}
              </div>
              <div className="flex items-center gap-1">
                <Calendar className="h-4 w-4" />
                {new Date(knowledge.created_at).toLocaleDateString('zh-CN')}
              </div>
              <div className="flex items-center gap-1">
                {getStatusIcon(knowledge.status)}
                {knowledge.status_text}
              </div>
            </div>
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          <Button variant="outline" className="flex items-center gap-2">
            <Share2 className="h-4 w-4" />
            分享
          </Button>
          <Button variant="outline" className="flex items-center gap-2">
            <Edit className="h-4 w-4" />
            编辑
          </Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Knowledge Content */}
          <Card>
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="space-y-2">
                  <div className="flex flex-wrap gap-2">
                    <Badge className={getCategoryBadgeColor(knowledge.category)}>
                      {knowledge.category_text}
                    </Badge>
                    <Badge variant="outline">
                      {knowledge.type_text}
                    </Badge>
                    {knowledge.severity && (
                      <Badge className={getSeverityBadgeColor(knowledge.severity)}>
                        {knowledge.severity_text}
                      </Badge>
                    )}
                  </div>
                  
                  {knowledge.summary && (
                    <p className="text-gray-600 text-lg">{knowledge.summary}</p>
                  )}
                </div>
                
                <div className="flex items-center gap-4 text-sm text-gray-500">
                  <div className="flex items-center gap-1">
                    <Eye className="h-4 w-4" />
                    {knowledge.view_count}
                  </div>
                  <button 
                    onClick={handleLike}
                    disabled={liked}
                    className={`flex items-center gap-1 transition-colors ${
                      liked ? 'text-red-500' : 'hover:text-red-500'
                    }`}
                  >
                    <Heart className={`h-4 w-4 ${liked ? 'fill-current' : ''}`} />
                    {knowledge.like_count}
                  </button>
                </div>
              </div>
            </CardHeader>
            
            <CardContent>
              <KnowledgeContentRenderer
                content={knowledge.content}
                contentType="html"
                showToolbar={true}
                editable={false}
              />
            </CardContent>
          </Card>

          {/* Tags */}
          {(knowledge.tags || []).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Tag className="h-5 w-5" />
                  标签
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {(knowledge.tags || []).map((tag) => (
                    <Badge
                      key={tag.id}
                      variant="outline"
                      className="cursor-pointer hover:bg-gray-100"
                    >
                      {tag.display_name}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Author Info */}
          <Card>
            <CardHeader>
              <CardTitle>作者信息</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                  <User className="h-6 w-6 text-blue-600" />
                </div>
                <div>
                  <p className="font-medium">{knowledge.author.real_name}</p>
                  <p className="text-sm text-gray-600">{knowledge.author.department}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Knowledge Stats */}
          <Card>
            <CardHeader>
              <CardTitle>统计信息</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-600">浏览次数</span>
                <span className="font-medium">{knowledge.view_count}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">点赞次数</span>
                <span className="font-medium">{knowledge.like_count}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">创建时间</span>
                <span className="font-medium">
                  {new Date(knowledge.created_at).toLocaleDateString('zh-CN')}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">更新时间</span>
                <span className="font-medium">
                  {new Date(knowledge.updated_at).toLocaleDateString('zh-CN')}
                </span>
              </div>
            </CardContent>
          </Card>

          {/* Related Knowledge */}
          {relatedKnowledge.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>相关知识</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {relatedKnowledge.map((item) => (
                    <div 
                      key={item.id}
                      className="p-3 border rounded-lg hover:bg-gray-50 cursor-pointer transition-colors"
                      onClick={() => navigate(`/knowledge/${item.id}`)}
                    >
                      <h4 className="font-medium text-sm line-clamp-2 mb-1">
                        {item.title}
                      </h4>
                      <div className="flex items-center gap-2 text-xs text-gray-500">
                        <Badge className={`${getCategoryBadgeColor(item.category)} text-xs`}>
                          {item.category_text}
                        </Badge>
                        <span>{item.view_count} 浏览</span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
