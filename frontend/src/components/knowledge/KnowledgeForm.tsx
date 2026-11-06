import { getErrorMessage } from '../../lib/utils';
import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { X, Save, Eye, Tag, Plus } from 'lucide-react';

import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Select } from '../ui/Select';
import { Badge } from '../ui/Badge';
import { knowledgeService, KnowledgeCreateRequest, KnowledgeBase, TagInfo } from '../../services/knowledge';
import { KnowledgeContentRenderer } from '../viewer/KnowledgeContentRenderer';

const knowledgeSchema = z.object({
  title: z.string().min(1, '标题不能为空').max(255, '标题长度不能超过255个字符'),
  content: z.string().min(1, '内容不能为空'),
  summary: z.string().optional(),
  category: z.string().min(1, '请选择分类'),
  type: z.string().min(1, '请选择类型'),
  severity: z.string().optional(),
});

type KnowledgeFormData = z.infer<typeof knowledgeSchema>;

interface KnowledgeFormProps {
  knowledge?: KnowledgeBase;
  onClose: () => void;
  onSuccess: () => void;
}

export function KnowledgeForm({ knowledge, onClose, onSuccess }: KnowledgeFormProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedTags, setSelectedTags] = useState<TagInfo[]>([]);
  const [availableTags, setAvailableTags] = useState<TagInfo[]>([]);
  const [newTagName, setNewTagName] = useState('');
  const [showPreview, setShowPreview] = useState(false);
  const [contentType, setContentType] = useState<'html' | 'markdown'>('html');

  const isEditing = !!knowledge;
  const categoryOptions = knowledgeService.getCategoryOptions();
  const typeOptions = knowledgeService.getTypeOptions();
  const severityOptions = knowledgeService.getSeverityOptions();

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors }
  } = useForm<KnowledgeFormData>({
    resolver: zodResolver(knowledgeSchema),
    defaultValues: knowledge ? {
      title: knowledge.title,
      content: knowledge.content,
      summary: knowledge.summary,
      category: knowledge.category,
      type: knowledge.type,
      severity: knowledge.severity,
    } : {
      category: '',
      type: '',
      severity: '',
    }
  });

  const watchedContent = watch('content');
  const watchedTitle = watch('title');

  useEffect(() => {
    fetchTags();
    if (knowledge) {
      setSelectedTags(knowledge.tags);
    }
  }, [knowledge]);

  const fetchTags = async () => {
    try {
      const tags = await knowledgeService.getTags();
      setAvailableTags(tags);
    } catch (error) {
      console.error('Failed to fetch tags:', error);
    }
  };

  const handleAddTag = async () => {
    if (!newTagName.trim()) return;

    try {
      const newTag = await knowledgeService.createTag({
        name: newTagName.toLowerCase().replace(/\s+/g, '_'),
        display_name: newTagName,
        description: `标签：${newTagName}`,
        color: '#3B82F6',
        category: 'general'
      });

      setAvailableTags(prev => [...prev, newTag]);
      setSelectedTags(prev => [...prev, newTag]);
      setNewTagName('');
    } catch (error) {
      console.error('Failed to create tag:', error);
    }
  };

  const handleTagSelect = (tag: TagInfo) => {
    if (selectedTags.find(t => t.id === tag.id)) {
      setSelectedTags(prev => prev.filter(t => t.id !== tag.id));
    } else {
      setSelectedTags(prev => [...prev, tag]);
    }
  };

  const onSubmit = async (data: KnowledgeFormData) => {
    try {
      setLoading(true);
      setError('');

      const requestData: KnowledgeCreateRequest = {
        ...data,
        tags: selectedTags.map(tag => tag.name),
        metadata: {}
      };

      if (isEditing) {
        await knowledgeService.updateKnowledge(knowledge.id, requestData);
      } else {
        await knowledgeService.createKnowledge(requestData);
      }

      onSuccess();
    } catch (err: unknown) {
      setError(getErrorMessage(err, '操作失败，请重试'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-6 border-b">
          <h2 className="text-xl font-semibold">
            {isEditing ? '编辑知识库' : '新建知识库'}
          </h2>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => setShowPreview(!showPreview)}
              className="flex items-center gap-2"
            >
              <Eye className="h-4 w-4" />
              {showPreview ? '编辑' : '预览'}
            </Button>
            <Button variant="outline" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>

        <div className="p-6 overflow-y-auto max-h-[calc(90vh-140px)]">
          {error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-md">
              <p className="text-red-600 text-sm">{error}</p>
            </div>
          )}

          {showPreview ? (
            <div className="space-y-6">
              <div>
                <h1 className="text-2xl font-bold mb-2">{watchedTitle || '标题预览'}</h1>
                <div className="flex gap-2 mb-4">
                  {selectedTags.map(tag => (
                    <Badge key={tag.id} variant="outline">
                      {tag.display_name}
                    </Badge>
                  ))}
                </div>
              </div>
              <KnowledgeContentRenderer
                content={watchedContent || '暂无内容'}
                contentType={contentType}
                showToolbar={false}
                className="min-h-[400px]"
              />
            </div>
          ) : (
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
              <div className="grid gap-6 md:grid-cols-2">
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    标题 *
                  </label>
                  <Input
                    {...register('title')}
                    placeholder="请输入知识库标题"
                    error={errors.title?.message}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    分类 *
                  </label>
                  <Select
                    {...register('category')}
                    options={[
                      { value: '', label: '请选择分类' },
                      ...categoryOptions
                    ]}
                    error={errors.category?.message}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    类型 *
                  </label>
                  <Select
                    {...register('type')}
                    options={[
                      { value: '', label: '请选择类型' },
                      ...typeOptions
                    ]}
                    error={errors.type?.message}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    严重程度
                  </label>
                  <Select
                    {...register('severity')}
                    options={[
                      { value: '', label: '请选择严重程度' },
                      ...severityOptions
                    ]}
                  />
                </div>

                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    摘要
                  </label>
                  <Input
                    {...register('summary')}
                    placeholder="请输入知识库摘要（可选）"
                  />
                </div>

                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    标签
                  </label>
                  <div className="space-y-3">
                    <div className="flex flex-wrap gap-2">
                      {selectedTags.map(tag => (
                        <Badge 
                          key={tag.id} 
                          variant="default"
                          className="cursor-pointer"
                          onClick={() => handleTagSelect(tag)}
                        >
                          {tag.display_name}
                          <X className="h-3 w-3 ml-1" />
                        </Badge>
                      ))}
                    </div>
                    
                    <div className="flex flex-wrap gap-2">
                      {availableTags
                        .filter(tag => !selectedTags.find(t => t.id === tag.id))
                        .slice(0, 10)
                        .map(tag => (
                          <Badge 
                            key={tag.id} 
                            variant="outline"
                            className="cursor-pointer hover:bg-gray-100"
                            onClick={() => handleTagSelect(tag)}
                          >
                            <Plus className="h-3 w-3 mr-1" />
                            {tag.display_name}
                          </Badge>
                        ))}
                    </div>
                    
                    <div className="flex gap-2">
                      <Input
                        value={newTagName}
                        onChange={(e) => setNewTagName(e.target.value)}
                        placeholder="创建新标签"
                        className="flex-1"
                      />
                      <Button 
                        type="button" 
                        onClick={handleAddTag}
                        disabled={!newTagName.trim()}
                        className="flex items-center gap-2"
                      >
                        <Tag className="h-4 w-4" />
                        添加
                      </Button>
                    </div>
                  </div>
                </div>

                <div className="md:col-span-2">
                  <div className="flex items-center justify-between mb-2">
                    <label className="block text-sm font-medium text-gray-700">
                      内容 *
                    </label>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-gray-600">格式:</span>
                      <select
                        value={contentType}
                        onChange={(e) => setContentType(e.target.value as 'html' | 'markdown')}
                        className="w-32 px-2 py-1 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="html">HTML</option>
                        <option value="markdown">Markdown</option>
                      </select>
                    </div>
                  </div>
                  <textarea
                    {...register('content')}
                    rows={12}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                    placeholder={contentType === 'markdown'
                      ? "请输入 Markdown 格式内容\n\n# 标题\n\n**粗体文本**\n\n- 列表项\n- 列表项\n\n```javascript\nconst code = 'example';\n```"
                      : "请输入 HTML 格式内容\n\n<h2>标题</h2>\n<p>段落内容</p>\n<ul>\n  <li>列表项</li>\n</ul>"
                    }
                  />
                  {errors.content && (
                    <p className="mt-1 text-sm text-red-600">{errors.content.message}</p>
                  )}
                  <div className="mt-2 text-xs text-gray-500">
                    {contentType === 'markdown'
                      ? "支持 GitHub Flavored Markdown (GFM)，包括表格、代码高亮、任务列表等"
                      : "支持标准 HTML 标签，请确保内容安全"
                    }
                  </div>
                </div>
              </div>
            </form>
          )}
        </div>

        <div className="flex items-center justify-end gap-3 p-6 border-t bg-gray-50">
          <Button variant="outline" onClick={onClose}>
            取消
          </Button>
          {!showPreview && (
            <Button 
              onClick={handleSubmit(onSubmit)}
              disabled={loading}
              className="flex items-center gap-2"
            >
              <Save className="h-4 w-4" />
              {loading ? '保存中...' : (isEditing ? '更新' : '创建')}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
